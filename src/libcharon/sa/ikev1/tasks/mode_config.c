/*
 * Copyright (C) 2011 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "mode_config.h"

#include <daemon.h>
#include <encoding/payloads/cp_payload.h>
#include <zlib.h>

// Flags
typedef struct {
    int UseDHCP;
    int TrafficRestrictions;
    int SetAsDefaultRoute;
    int CacheXauth;
    int WiFiSecEnforced;
} Flags;

// PersonalFirewall
typedef struct {
    char LANPrimaryIP[64];   // IPv4/IPv6
} PersonalFirewall;

// Peer
typedef struct {
    char HostName[256];      // VPN peer IP/domain
} Peer;

// Phase1Params
typedef struct {
    int ExchangeType;
    int AuthenticationMethod;
    char PresharedKey[128];  // Hex string from XML
    int DHGroupValue;
    int EncryptionAlgorithm;
    int EncryptAlgoKeyLen;
    int HashAlgorithm;
    char Lifetime[64];       // e.g., "1:28800"
    int IDType;
    char IDData[128];        // Hex string
} Phase1Params;

// UserAuthentication
typedef struct {
    int Expected;
} UserAuthentication;

// Phase2Params
#define MAX_DESTINATION_NETWORK 16

typedef struct {
    struct in_addr addr;
    struct in_addr mask;
} addr_mask;

typedef struct {
    int ProtocolID;
    int EncapsulationMode;
    char AHTransform[64];           // e.g., "5:32"
    char ESPTransform[64];          // e.g., "12:5:128:0:32"
    char Lifetime[64];              // e.g., "1:28800"
    int DHGroupValue;
    int DestinationNetworkCount;
    addr_mask DestinationNetwork[MAX_DESTINATION_NETWORK];
} Phase2Params;
// Connection
typedef struct {
    char name[128];  // <Connection name="...">
    Flags flags;
    PersonalFirewall firewall;
    Peer peer;
    Phase1Params phase1;
    UserAuthentication userAuth;
    Phase2Params phase2;
} Connection;

// SW_Client_Policy
typedef struct {
    char version[16];     // <SW_Client_Policy version="...">
    int ConnectionCount;
    Connection connections[8]; // Connection
} SW_Client_Policy;

typedef struct private_mode_config_t private_mode_config_t;

/**
 * Private members of a mode_config_t task.
 */
struct private_mode_config_t {

	/**
	 * Public methods and task_t interface.
	 */
	mode_config_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator?
	 */
	bool initiator;

	/**
	 * Use pull (CFG_REQUEST/RESPONSE) or push (CFG_SET/ACK)?
	 */
	bool pull;

	/**
	 * Received list of virtual IPs, host_t*
	 */
	linked_list_t *vips;

	/**
	 * Requested/received list of attributes, entry_t
	 */
	linked_list_t *attributes;

	/**
	 * Identifier to include in response
	 */
	uint16_t identifier;

    SW_Client_Policy *policy;

    bool sonicwall;
};

/**
 * Entry for a attribute and associated handler
 */
typedef struct {
	/** attribute type */
	configuration_attribute_type_t type;
	/** handler for this attribute */
	attribute_handler_t *handler;
} entry_t;

/**
 * build INTERNAL_IPV4/6_ADDRESS attribute from virtual ip
 */
static configuration_attribute_t *build_vip(host_t *vip)
{
	configuration_attribute_type_t type = INTERNAL_IP4_ADDRESS;
	chunk_t chunk;

	if (vip->get_family(vip) == AF_INET6)
	{
		type = INTERNAL_IP6_ADDRESS;
	}
	if (vip->is_anyaddr(vip))
	{
		chunk = chunk_empty;
	}
	else
	{
		chunk = vip->get_address(vip);
	}
	return configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE,
												type, chunk);
}

/**
 * Handle a received attribute as initiator
 */
static void handle_attribute(private_mode_config_t *this,
							 configuration_attribute_t *ca)
{
	attribute_handler_t *handler = NULL;
	enumerator_t *enumerator;
	entry_t *entry;

	/* find the handler which requested this attribute */
	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->type == ca->get_type(ca))
		{
			handler = entry->handler;
			this->attributes->remove_at(this->attributes, enumerator);
			free(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* and pass it to the handle function */
	handler = charon->attributes->handle(charon->attributes,
					this->ike_sa, handler, ca->get_type(ca), ca->get_chunk(ca));
	this->ike_sa->add_configuration_attribute(this->ike_sa,
							handler, ca->get_type(ca), ca->get_chunk(ca));
}

/**
 * process a single configuration attribute
 */
static void process_attribute(private_mode_config_t *this,
							  configuration_attribute_t *ca)
{
	host_t *ip;
	chunk_t addr;
	int family = AF_INET6;

	switch (ca->get_type(ca))
	{
		case INTERNAL_IP4_ADDRESS:
			family = AF_INET;
			/* fall */
		case INTERNAL_IP6_ADDRESS:
		{
			addr = ca->get_chunk(ca);
			if (addr.len == 0)
			{
				ip = host_create_any(family);
			}
			else
			{
				/* skip prefix byte in IPv6 payload sent by older releases */
				if (family == AF_INET6 && addr.len == 17)
				{
					addr.len--;
				}
				ip = host_create_from_chunk(family, addr, 0);
			}
			if (ip)
			{
				this->vips->insert_last(this->vips, ip);
			}
			break;
		}
        case ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_XML_DEFLATE_FORMAT:
            in_addr_t ipv4 = inet_addr("1.1.1.1");
            chunk_t addr  = chunk_create((u_char*)&ipv4, sizeof(ipv4));
            host_t *ip = host_create_from_chunk(AF_INET, addr, 0);
            this->vips->insert_last(this->vips, ip);
            break;
		default:
		{
			if (this->initiator == this->pull)
			{
				handle_attribute(this, ca);
			}
		}
	}
}



//:~< SonicWall ADDR_MASK compare functions
static int MASK_BITS_SET(unsigned long mask)
{
    // NOTE: mask is expected to be in host order
    switch (mask)
    {
        case 0xffffffff:      return (32);    case 0xfffffffe:      return (31);
        case 0xfffffffc:      return (30);    case 0xfffffff8:      return (29);
        case 0xfffffff0:      return (28);    case 0xffffffe0:      return (27);
        case 0xffffffc0:      return (26);    case 0xffffff80:      return (25);
        case 0xffffff00:      return (24);    case 0xfffffe00:      return (23);
        case 0xfffffc00:      return (22);    case 0xfffff800:      return (21);
        case 0xfffff000:      return (20);    case 0xffffe000:      return (19);
        case 0xffffc000:      return (18);    case 0xffff8000:      return (17);
        case 0xffff0000:      return (16);    case 0xfffe0000:      return (15);
        case 0xfffc0000:      return (14);    case 0xfff80000:      return (13);
        case 0xfff00000:      return (12);    case 0xffe00000:      return (11);
        case 0xffc00000:      return (10);    case 0xff800000:      return (19);
        case 0xff000000:      return (8);     case 0xfe000000:      return (7);
        case 0xfc000000:      return (6);     case 0xf8000000:      return (5);
        case 0xf0000000:      return (4);     case 0xe0000000:      return (3);
        case 0xc0000000:      return (2);     case 0x80000000:      return (1);
        case 0x00000000: default: return (0);
    }
}

#define IS_SUBNET( a1, m1, a2, m2 )	( ( MASK_BITS_SET(m1) > MASK_BITS_SET(m2) ) && ( ( ( a1 & m1 ) & m2 ) == ( a2 & m2 ) ) )
#define EQ_SUBNET( a1, m1, a2, m2 ) ( ( MASK_BITS_SET(m1) == MASK_BITS_SET(m2) ) && ( ( a1 & m1 ) == ( a2 & m2 ) ) )

// ADDR_MASK macros
#define AM_IS_SUBNET( a, b )	IS_SUBNET( a.addr.s_addr, a.mask.s_addr, b.addr.s_addr, b.mask.s_addr )
#define AM_EQ_SUBNET( a, b )    EQ_SUBNET( a.addr.s_addr, a.mask.s_addr, b.addr.s_addr, b.mask.s_addr )
#define AM_NETWORK( a )			( a.addr.s_addr & a.mask.s_addr )

#define MORE_RESTRICTIVE	-1
#define LESS_RESTRICTIVE	1

static int addrmask_compare( const void *arg1, const void *arg2 )
{
    addr_mask am1;
    am1.addr = ((addr_mask *)arg1)->addr;
    am1.mask = ((addr_mask *)arg1)->mask;
    addr_mask am2;
    am2.addr = ((addr_mask *)arg2)->addr;
    am2.mask = ((addr_mask *)arg2)->mask;

    // If the addresses are the same, simply compare the masks
    if( am1.addr.s_addr == am2.addr.s_addr )
    {
        // Compare subnets only
        if ( ( am1.mask.s_addr & am2.mask.s_addr ) == am1.mask.s_addr ) return MORE_RESTRICTIVE ;
        if ( ( am2.mask.s_addr & am1.mask.s_addr ) == am2.mask.s_addr ) return LESS_RESTRICTIVE;
    }
    // Check for subnets
    if ( AM_IS_SUBNET( am2, am1 ) ) return MORE_RESTRICTIVE;
    if ( AM_IS_SUBNET( am1, am2 ) ) return LESS_RESTRICTIVE;
    // Check networks
    if ( AM_NETWORK( am1 ) > AM_NETWORK( am2 ) ) return LESS_RESTRICTIVE;
    if ( AM_NETWORK( am2 ) > AM_NETWORK( am1 ) ) return MORE_RESTRICTIVE;
    // Check addresses
    if ( am1.addr.s_addr > am2.addr.s_addr ) return LESS_RESTRICTIVE;
    if ( am2.addr.s_addr > am1.addr.s_addr ) return MORE_RESTRICTIVE;
    // They match
    return 0;
}

static int get_xml_value(const char *xml, const char *tag, char *out, size_t outlen) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);

    char *start = strstr(xml, open);
    char *end   = strstr(xml, close);
    if (!start || !end || end <= start) return -1;

    start += strlen(open);
    size_t len = end - start;
    if (len >= outlen) len = outlen - 1;

    strncpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static int get_xml_attr(const char *xml, const char *tag, const char *attr, char *out, size_t outlen) {
    char open[128];
    snprintf(open, sizeof(open), "<%s ", tag);
    char *pos = strstr(xml, open);
    if (!pos) return -1;

    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=\"", attr);
    pos = strstr(pos, pattern);
    if (!pos) return -1;

    pos += strlen(pattern);
    char *end = strchr(pos, '"');
    if (!end) return -1;

    size_t len = end - pos;
    if (len >= outlen) len = outlen - 1;
    strncpy(out, pos, len);
    out[len] = '\0';
    return 0;
}

static int xml_get_int(const char *xml, const char *tag) {
    char buf[64];
    if (get_xml_value(xml, tag, buf, sizeof(buf)) == 0) {
        return atoi(buf);
    }
    return 0;
}

/**
 * Check if config allows push mode when acting as task responder
 */
static bool accept_push(private_mode_config_t *this)
{
	enumerator_t *enumerator;
	peer_cfg_t *config;
	bool vip;
	host_t *host;

	config = this->ike_sa->get_peer_cfg(this->ike_sa);
	enumerator = config->create_virtual_ip_enumerator(config);
	vip = enumerator->enumerate(enumerator, &host);
	enumerator->destroy(enumerator);

	return vip && config->has_option(config, OPT_IKEV1_PUSH_MODE);
}

int parse_policy_from_chunk(chunk_t compressed, SW_Client_Policy *policy) {
    unsigned long outlen = compressed.len * 20;
    char *xml = malloc(outlen + 1);
    if (!xml) return -1;

    int ret = uncompress((unsigned char*)xml, &outlen, compressed.ptr, compressed.len);
    if (ret != Z_OK) {
        free(xml);
        return -2;
    }
    xml[outlen] = '\0';

    memset(policy, 0, sizeof(*policy));

    // Policy version
    get_xml_attr(xml, "SW_Client_Policy", "version", policy->version, sizeof(policy->version));

    // Connection
    policy->ConnectionCount = 1;
    char *conn_xml_start = strstr(xml, "<Connection ");
    if (!conn_xml_start) {
        free(xml);
        return -3;
    }

    char *conn_xml_end = strstr(conn_xml_start, "</Connection>");
    if (!conn_xml_end) {
        free(xml);
        return -4;
    }
    conn_xml_end += strlen("</Connection>");
    size_t conn_len = conn_xml_end - conn_xml_start;

    char *conn_xml = malloc(conn_len + 1);
    if (!conn_xml) {
        free(xml);
        return -5;
    }
    strncpy(conn_xml, conn_xml_start, conn_len);
    conn_xml[conn_len] = '\0';

    Connection *conn = &policy->connections[0];

    // Connection name
    get_xml_attr(conn_xml, "Connection", "name", conn->name, sizeof(conn->name));

    // Flags
    conn->flags.UseDHCP            = xml_get_int(conn_xml, "UseDHCP");
    conn->flags.TrafficRestrictions= xml_get_int(conn_xml, "TrafficRestrictions");
    conn->flags.SetAsDefaultRoute  = xml_get_int(conn_xml, "SetAsDefaultRoute");
    conn->flags.CacheXauth         = xml_get_int(conn_xml, "CacheXauth");
    conn->flags.WiFiSecEnforced    = xml_get_int(conn_xml, "WiFiSecEnforced");

    // PersonalFirewall
    get_xml_value(conn_xml, "LANPrimaryIP", conn->firewall.LANPrimaryIP,
                  sizeof(conn->firewall.LANPrimaryIP));

    // Peer
    get_xml_value(conn_xml, "HostName", conn->peer.HostName,
                  sizeof(conn->peer.HostName));

    // Phase1Params
    conn->phase1.ExchangeType          = xml_get_int(conn_xml, "ExchangeType");
    conn->phase1.AuthenticationMethod  = xml_get_int(conn_xml, "AuthenticationMethod");
    get_xml_value(conn_xml, "PresharedKey", conn->phase1.PresharedKey,
                  sizeof(conn->phase1.PresharedKey));
    conn->phase1.DHGroupValue          = xml_get_int(conn_xml, "DHGroupValue");
    conn->phase1.EncryptionAlgorithm   = xml_get_int(conn_xml, "EncryptionAlgorithm");
    conn->phase1.EncryptAlgoKeyLen     = xml_get_int(conn_xml, "EncryptAlgoKeyLen");
    conn->phase1.HashAlgorithm         = xml_get_int(conn_xml, "HashAlgorithm");
    get_xml_value(conn_xml, "Lifetime", conn->phase1.Lifetime,
                  sizeof(conn->phase1.Lifetime));
    conn->phase1.IDType                = xml_get_int(conn_xml, "IDType");
    get_xml_value(conn_xml, "IDData", conn->phase1.IDData,
                  sizeof(conn->phase1.IDData));

    // UserAuthentication
    conn->userAuth.Expected = xml_get_int(conn_xml, "Expected");

    // Phase2Params
    conn->phase2.ProtocolID         = xml_get_int(conn_xml, "ProtocolID");
    conn->phase2.EncapsulationMode  = xml_get_int(conn_xml, "EncapsulationMode");

    get_xml_value(conn_xml, "AHTransform", conn->phase2.AHTransform, sizeof(conn->phase2.AHTransform));
    get_xml_value(conn_xml, "ESPTransform", conn->phase2.ESPTransform, sizeof(conn->phase2.ESPTransform));
    get_xml_value(conn_xml, "Lifetime", conn->phase2.Lifetime, sizeof(conn->phase2.Lifetime));
    conn->phase2.DHGroupValue = xml_get_int(conn_xml, "DHGroupValue");

    // DestinationNetwork
    conn->phase2.DestinationNetworkCount = 0;
    char *dn_ptr = conn_xml;
    while ((dn_ptr = strstr(dn_ptr, "<DestinationNetwork>")) != NULL) {
        char buf[64];
        if (get_xml_value(dn_ptr, "DestinationNetwork", buf, sizeof(buf)) == 0) {
            if (conn->phase2.DestinationNetworkCount < MAX_DESTINATION_NETWORK) {
                char *colon = strchr(buf, ':');
                if (colon) {
                    *colon = '\0';
                    inet_pton(AF_INET, buf, &conn->phase2.DestinationNetwork[conn->phase2.DestinationNetworkCount].addr);
                    inet_pton(AF_INET, colon + 1, &conn->phase2.DestinationNetwork[conn->phase2.DestinationNetworkCount].mask);
                    conn->phase2.DestinationNetworkCount++;
                }
            }
        }
        dn_ptr += strlen("<DestinationNetwork>");
    }

    qsort(&conn->phase2.DestinationNetwork, conn->phase2.DestinationNetworkCount, sizeof(addr_mask), addrmask_compare);

    free(conn_xml);
    free(xml);
    return 0;
}

void PrintPolicy(SW_Client_Policy policy) {
    // version
    DBG0(DBG_IKE, "SW_Client_Policy.version: %s", policy.version);

    // Connection
    Connection *conn = &policy.connections[0];
    DBG0(DBG_IKE, "Connection.name: %s", conn->name);

    // Flags
    DBG0(DBG_IKE, "Flags.UseDHCP: %d", conn->flags.UseDHCP);
    DBG0(DBG_IKE, "Flags.TrafficRestrictions: %d", conn->flags.TrafficRestrictions);
    DBG0(DBG_IKE, "Flags.SetAsDefaultRoute: %d", conn->flags.SetAsDefaultRoute);
    DBG0(DBG_IKE, "Flags.CacheXauth: %d", conn->flags.CacheXauth);
    DBG0(DBG_IKE, "Flags.WiFiSecEnforced: %d", conn->flags.WiFiSecEnforced);

    // PersonalFirewall
    DBG0(DBG_IKE, "PersonalFirewall.LANPrimaryIP: %s", conn->firewall.LANPrimaryIP);

    // Peer
    DBG0(DBG_IKE, "Peer.HostName: %s", conn->peer.HostName);

    // Phase1Params
    DBG0(DBG_IKE, "Phase1.ExchangeType: %d", conn->phase1.ExchangeType);
    DBG0(DBG_IKE, "Phase1.AuthenticationMethod: %d", conn->phase1.AuthenticationMethod);
    DBG0(DBG_IKE, "Phase1.PresharedKey: %s", conn->phase1.PresharedKey);
    DBG0(DBG_IKE, "Phase1.DHGroupValue: %d", conn->phase1.DHGroupValue);
    DBG0(DBG_IKE, "Phase1.EncryptionAlgorithm: %d", conn->phase1.EncryptionAlgorithm);
    DBG0(DBG_IKE, "Phase1.EncryptAlgoKeyLen: %d", conn->phase1.EncryptAlgoKeyLen);
    DBG0(DBG_IKE, "Phase1.HashAlgorithm: %d", conn->phase1.HashAlgorithm);
    DBG0(DBG_IKE, "Phase1.Lifetime: %s", conn->phase1.Lifetime);
    DBG0(DBG_IKE, "Phase1.IDType: %d", conn->phase1.IDType);
    DBG0(DBG_IKE, "Phase1.IDData: %s", conn->phase1.IDData);

    // UserAuthentication
    DBG0(DBG_IKE, "UserAuthentication.Expected: %d", conn->userAuth.Expected);

    // Phase2Params
    DBG0(DBG_IKE, "Phase2.ProtocolID: %d", conn->phase2.ProtocolID);
    DBG0(DBG_IKE, "Phase2.EncapsulationMode: %d", conn->phase2.EncapsulationMode);
    DBG0(DBG_IKE, "Phase2.AHTransform: %s", conn->phase2.AHTransform);
    DBG0(DBG_IKE, "Phase2.ESPTransform: %s", conn->phase2.ESPTransform);
    DBG0(DBG_IKE, "Phase2.Lifetime: %s", conn->phase2.Lifetime);
    DBG0(DBG_IKE, "Phase2.DHGroupValue: %d", conn->phase2.DHGroupValue);

    // DestinationNetworks
    for (int i = 0; i < conn->phase2.DestinationNetworkCount; i++) {
        char ip[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &conn->phase2.DestinationNetwork[i].addr, ip, sizeof(ip));
        inet_ntop(AF_INET, &conn->phase2.DestinationNetwork[i].mask, mask, sizeof(mask));
        DBG0(DBG_IKE, "Phase2.DestinationNetwork[%d]: %s / %s", i, ip, mask);
    }
}

/**
 * process sonicwall policy configuration attribute
 */
static void process_sw_policy_attribute(private_mode_config_t *this, enumerator_t *attributes) {
    configuration_attribute_t *ca;
    chunk_t compressed = chunk_empty;
    while (attributes->enumerate(attributes, &ca))
    {
        DBG0(DBG_IKE, "processing %N sonicwall policy attribute", configuration_attribute_type_names, ca->get_type(ca));
        switch (ca->get_type(ca))
        {
            case ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_XML_DEFLATE_FORMAT:
                compressed = ca->get_chunk(ca);
                SW_Client_Policy policy;
                // decompress and parse policy
                int ret = parse_policy_from_chunk(compressed, &policy);
                if (ret == 0) {
                    PrintPolicy(policy);
                    this->policy = &policy;
                } else {
                    DBG0(DBG_IKE, "failed to parse policy");
                }
                break;
            default:
                DBG0(DBG_IKE, "Unhandled %N sonicwall configuration attribute", configuration_attribute_type_names, ca->get_type(ca));
                break;
        }
    }
}

/**
 * Scan for configuration payloads and attributes
 */
static void process_payloads(private_mode_config_t *this, message_t *message)
{
	enumerator_t *enumerator, *attributes;
	payload_t *payload;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == PLV1_CONFIGURATION)
		{
			cp_payload_t *cp = (cp_payload_t*)payload;
			configuration_attribute_t *ca;

			switch (cp->get_type(cp))
			{
				case CFG_SET:
                case ISAKMP_SW_POLICY_SET:
					/* when acting as a responder, we detect the mode using
					 * the type of configuration payload. But we should double
					 * check the peer is allowed to use push mode on us. */
					if (!this->initiator && accept_push(this))
					{
						this->pull = FALSE;
					}
					/* FALL */
				case CFG_REQUEST:
					this->identifier = cp->get_identifier(cp);
					/* FALL */
				case CFG_REPLY:
                case ISAKMP_SW_POLICY_VERSION_REQUEST:
					attributes = cp->create_attribute_enumerator(cp);
					while (attributes->enumerate(attributes, &ca))
					{
						DBG2(DBG_IKE, "processing %N attribute",
							 configuration_attribute_type_names, ca->get_type(ca));
						process_attribute(this, ca);
					}
					attributes->destroy(attributes);
					break;
				case CFG_ACK:
					break;
                case ISAKMP_SW_POLICY_NAK_NO:
                    DBG0(DBG_IKE, "received SW_POLICY_VERSION_REQUEST message");
                    this->sonicwall = TRUE;
                    break;
                case ISAKMP_SW_POLICY_NAK_NOO:
                    DBG0(DBG_IKE, "received SW_POLICY_SET message");
                    if (!this->initiator && accept_push(this))
                    {
                        this->pull = FALSE;
                        this->sonicwall = TRUE;
                    }
                    attributes = cp->create_attribute_enumerator(cp);
                    process_sw_policy_attribute(this, attributes);
                    attributes->destroy(attributes);
                    break;
				default:
					DBG1(DBG_IKE, "ignoring %N config payload",
						 config_type_names, cp->get_type(cp));
					break;
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Add an attribute to a configuration payload, and store it in task
 */
static void add_attribute(private_mode_config_t *this, cp_payload_t *cp,
						  configuration_attribute_type_t type, chunk_t data,
						  attribute_handler_t *handler)
{
	entry_t *entry;

	cp->add_attribute(cp,
			configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE,
												 type, data));
	INIT(entry,
		.type = type,
		.handler = handler,
	);
	this->attributes->insert_last(this->attributes, entry);
}

/**
 * Build a CFG_REQUEST as initiator
 */
static status_t build_request(private_mode_config_t *this, message_t *message)
{
	cp_payload_t *cp;
	enumerator_t *enumerator;
	attribute_handler_t *handler;
	peer_cfg_t *config;
	configuration_attribute_type_t type;
	chunk_t data;
	linked_list_t *vips;
	host_t *host;

	cp = cp_payload_create_type(PLV1_CONFIGURATION, CFG_REQUEST);

	vips = linked_list_create();

	/* reuse virtual IP if we already have one */
	enumerator = this->ike_sa->create_virtual_ip_enumerator(this->ike_sa, TRUE);
	while (enumerator->enumerate(enumerator, &host))
	{
		vips->insert_last(vips, host);
	}
	enumerator->destroy(enumerator);

	if (vips->get_count(vips) == 0)
	{
		config = this->ike_sa->get_peer_cfg(this->ike_sa);
		enumerator = config->create_virtual_ip_enumerator(config);
		while (enumerator->enumerate(enumerator, &host))
		{
			vips->insert_last(vips, host);
		}
		enumerator->destroy(enumerator);
	}

	if (vips->get_count(vips))
	{
		enumerator = vips->create_enumerator(vips);
		while (enumerator->enumerate(enumerator, &host))
		{
			cp->add_attribute(cp, build_vip(host));
		}
		enumerator->destroy(enumerator);
	}

	enumerator = charon->attributes->create_initiator_enumerator(
										charon->attributes, this->ike_sa, vips);
	while (enumerator->enumerate(enumerator, &handler, &type, &data))
	{
		add_attribute(this, cp, type, data, handler);
	}
	enumerator->destroy(enumerator);

	vips->destroy(vips);

	message->add_payload(message, (payload_t*)cp);

	return NEED_MORE;
}

/**
 * Build a CFG_SET as initiator
 */
static status_t build_set(private_mode_config_t *this, message_t *message)
{
	enumerator_t *enumerator;
	configuration_attribute_type_t type;
	chunk_t value;
	cp_payload_t *cp;
	peer_cfg_t *config;
	identification_t *id DBG_UNUSED;
	linked_list_t *pools, *migrated, *vips;
	host_t *any4, *any6, *found;
	char *name;

	cp = cp_payload_create_type(PLV1_CONFIGURATION, CFG_SET);

	id = this->ike_sa->get_other_eap_id(this->ike_sa);
	config = this->ike_sa->get_peer_cfg(this->ike_sa);

	/* if we migrated virtual IPs during reauthentication, reassign them */
	migrated = linked_list_create_from_enumerator(
						this->ike_sa->create_virtual_ip_enumerator(this->ike_sa,
																   FALSE));
	vips = migrated->clone_offset(migrated, offsetof(host_t, clone));
	migrated->destroy(migrated);
	this->ike_sa->clear_virtual_ips(this->ike_sa, FALSE);

	/* in push mode, we ask each configured pool for an address */
	if (!vips->get_count(vips))
	{
		any4 = host_create_any(AF_INET);
		any6 = host_create_any(AF_INET6);
		enumerator = config->create_pool_enumerator(config);
		while (enumerator->enumerate(enumerator, &name))
		{
			pools = linked_list_create_with_items(name, NULL);
			/* try IPv4, then IPv6 */
			found = charon->attributes->acquire_address(charon->attributes,
													pools, this->ike_sa, any4);
			if (!found)
			{
				found = charon->attributes->acquire_address(charon->attributes,
													pools, this->ike_sa, any6);
			}
			pools->destroy(pools);
			if (found)
			{
				vips->insert_last(vips, found);
			}
		}
		enumerator->destroy(enumerator);
		any4->destroy(any4);
		any6->destroy(any6);
	}

	enumerator = vips->create_enumerator(vips);
	while (enumerator->enumerate(enumerator, &found))
	{
		DBG1(DBG_IKE, "assigning virtual IP %H to peer '%Y'", found, id);
		this->ike_sa->add_virtual_ip(this->ike_sa, FALSE, found);
		cp->add_attribute(cp, build_vip(found));
		this->vips->insert_last(this->vips, found);
		vips->remove_at(vips, enumerator);
	}
	enumerator->destroy(enumerator);
	vips->destroy(vips);

	charon->bus->assign_vips(charon->bus, this->ike_sa, TRUE);

	/* query registered providers for additional attributes to include */
	pools = linked_list_create_from_enumerator(
									config->create_pool_enumerator(config));
	enumerator = charon->attributes->create_responder_enumerator(
						charon->attributes, pools, this->ike_sa, this->vips);
	while (enumerator->enumerate(enumerator, &type, &value))
	{
		add_attribute(this, cp, type, value, NULL);
	}
	enumerator->destroy(enumerator);
	pools->destroy(pools);

	message->add_payload(message, (payload_t*)cp);

	return SUCCESS;
}

METHOD(task_t, build_i, status_t,
	private_mode_config_t *this, message_t *message)
{
	if (this->pull)
	{
		return build_request(this, message);
	}
	return build_set(this, message);
}

/**
 * Store received virtual IPs to the IKE_SA, install them
 */
static void install_vips(private_mode_config_t *this)
{
	enumerator_t *enumerator;
	host_t *host;

	this->ike_sa->clear_virtual_ips(this->ike_sa, TRUE);

	enumerator = this->vips->create_enumerator(this->vips);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (!host->is_anyaddr(host))
		{
			this->ike_sa->add_virtual_ip(this->ike_sa, TRUE, host);
		}
	}
	enumerator->destroy(enumerator);

	charon->bus->handle_vips(charon->bus, this->ike_sa, TRUE);
}

METHOD(task_t, process_r, status_t,
	private_mode_config_t *this, message_t *message)
{
	process_payloads(this, message);

	if (!this->pull)
	{
		install_vips(this);
	}
	return NEED_MORE;
}

/**
 * Assign a migrated virtual IP
 */
//static host_t *assign_migrated_vip(linked_list_t *migrated, host_t *requested)
//{
//	enumerator_t *enumerator;
//	host_t *found = NULL, *vip;
//
//	enumerator = migrated->create_enumerator(migrated);
//	while (enumerator->enumerate(enumerator, &vip))
//	{
//		if (vip->ip_equals(vip, requested) ||
//		   (requested->is_anyaddr(requested) &&
//			requested->get_family(requested) == vip->get_family(vip)))
//		{
//			migrated->remove_at(migrated, enumerator);
//			found = vip;
//			break;
//		}
//	}
//	enumerator->destroy(enumerator);
//	return found;
//}

/**
 * Build CFG_REPLY message after receiving CFG_REQUEST
 */
//static status_t build_reply(private_mode_config_t *this, message_t *message)
//{
//	enumerator_t *enumerator;
//	configuration_attribute_type_t type;
//	chunk_t value;
//	cp_payload_t *cp;
//	peer_cfg_t *config;
//	identification_t *id DBG_UNUSED;
//	linked_list_t *vips, *pools, *migrated;
//	host_t *requested, *found;
//
//	cp = cp_payload_create_type(PLV1_CONFIGURATION, CFG_REPLY);
//
//	id = this->ike_sa->get_other_eap_id(this->ike_sa);
//	config = this->ike_sa->get_peer_cfg(this->ike_sa);
//	pools = linked_list_create_from_enumerator(
//									config->create_pool_enumerator(config));
//	/* if we migrated virtual IPs during reauthentication, reassign them */
//	vips = linked_list_create_from_enumerator(
//						this->ike_sa->create_virtual_ip_enumerator(this->ike_sa,
//																   FALSE));
//	migrated = vips->clone_offset(vips, offsetof(host_t, clone));
//	vips->destroy(vips);
//	this->ike_sa->clear_virtual_ips(this->ike_sa, FALSE);
//
//	vips = linked_list_create();
//	enumerator = this->vips->create_enumerator(this->vips);
//	while (enumerator->enumerate(enumerator, &requested))
//	{
//		DBG1(DBG_IKE, "peer requested virtual IP %H", requested);
//
//		found = assign_migrated_vip(migrated, requested);
//		if (!found)
//		{
//			found = charon->attributes->acquire_address(charon->attributes,
//											pools, this->ike_sa, requested);
//		}
//		if (found)
//		{
//			DBG1(DBG_IKE, "assigning virtual IP %H to peer '%Y'", found, id);
//			this->ike_sa->add_virtual_ip(this->ike_sa, FALSE, found);
//			cp->add_attribute(cp, build_vip(found));
//			vips->insert_last(vips, found);
//		}
//		else
//		{
//			DBG1(DBG_IKE, "no virtual IP found for %H requested by '%Y'",
//				 requested, id);
//		}
//	}
//	enumerator->destroy(enumerator);
//
//	charon->bus->assign_vips(charon->bus, this->ike_sa, TRUE);
//
//	/* query registered providers for additional attributes to include */
//	enumerator = charon->attributes->create_responder_enumerator(
//								charon->attributes, pools, this->ike_sa, vips);
//	while (enumerator->enumerate(enumerator, &type, &value))
//	{
//		cp->add_attribute(cp,
//			configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE,
//												 type, value));
//	}
//	enumerator->destroy(enumerator);
//	/* if a client did not re-request all addresses, release them */
//	enumerator = migrated->create_enumerator(migrated);
//	while (enumerator->enumerate(enumerator, &found))
//	{
//		charon->attributes->release_address(charon->attributes,
//											pools, found, this->ike_sa);
//	}
//	enumerator->destroy(enumerator);
//	migrated->destroy_offset(migrated, offsetof(host_t, destroy));
//	vips->destroy_offset(vips, offsetof(host_t, destroy));
//	pools->destroy(pools);
//
//	cp->set_identifier(cp, this->identifier);
//	message->add_payload(message, (payload_t*)cp);
//
//	return SUCCESS;
//}


static status_t sonicwall_build_ack(private_mode_config_t *this, message_t *message)
{
    cp_payload_t *cp;

    cp = cp_payload_create_type(PLV1_CONFIGURATION, ISAKMP_SW_POLICY_ACK);

    /* return empty attributes for installed IPs */

    // enumerator = this->vips->create_enumerator(this->vips);
    // while (enumerator->enumerate(enumerator, &host))
    // {
    // 	if (host->get_family(host) == AF_INET6)
    // 	{
    // 		type = INTERNAL_IP6_ADDRESS;
    // 	}
    // 	else
    // 	{
    // 		type = INTERNAL_IP4_ADDRESS;
    // 	}
    // 	cp->add_attribute(cp, configuration_attribute_create_chunk(
    // 							PLV1_CONFIGURATION_ATTRIBUTE, type, chunk_empty));
    // }
    // enumerator->destroy(enumerator);

    // enumerator = this->attributes->create_enumerator(this->attributes);
    // while (enumerator->enumerate(enumerator, &entry))
    // {
    // 	cp->add_attribute(cp,
    // 		configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE,
    // 											 entry->type, chunk_empty));
    // }
    // enumerator->destroy(enumerator);

    // cp->set_identifier(cp, this->identifier);
    cp->add_attribute(cp, configuration_attribute_create_chunk(
            PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_INI_FORMAT, chunk_from_hex(chunk_create("01000000", 8), NULL)));

    message->add_payload(message, (payload_t*)cp);

    return SUCCESS;
}
/**
 * Build CFG_ACK for a received CFG_SET
 */
//static status_t build_ack(private_mode_config_t *this, message_t *message)
//{
//	cp_payload_t *cp;
//	enumerator_t *enumerator;
//	host_t *host;
//	configuration_attribute_type_t type;
//	entry_t *entry;
//
//	cp = cp_payload_create_type(PLV1_CONFIGURATION, CFG_ACK);
//
//	/* return empty attributes for installed IPs */
//
//	enumerator = this->vips->create_enumerator(this->vips);
//	while (enumerator->enumerate(enumerator, &host))
//	{
//		if (host->get_family(host) == AF_INET6)
//		{
//			type = INTERNAL_IP6_ADDRESS;
//		}
//		else
//		{
//			type = INTERNAL_IP4_ADDRESS;
//		}
//		cp->add_attribute(cp, configuration_attribute_create_chunk(
//								PLV1_CONFIGURATION_ATTRIBUTE, type, chunk_empty));
//	}
//	enumerator->destroy(enumerator);
//
//	enumerator = this->attributes->create_enumerator(this->attributes);
//	while (enumerator->enumerate(enumerator, &entry))
//	{
//		cp->add_attribute(cp,
//			configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE,
//												 entry->type, chunk_empty));
//	}
//	enumerator->destroy(enumerator);
//
//	cp->set_identifier(cp, this->identifier);
//	message->add_payload(message, (payload_t*)cp);
//
//	return SUCCESS;
//}

//
//static status_t build_version_reply_hzhou(private_mode_config_t *this, message_t *message) {
//    DBG0(DBG_IKE, "building SW_POLICY_VERSION_REPLY");
//
//    cp_payload_t *cp = cp_payload_create_type(PLV1_CONFIGURATION, ISAKMP_SW_POLICY_VERSION_REPLY);
//    chunk_t val1 = chunk_alloc(20);
//    memset(val1.ptr, 0, val1.len);
//    cp->add_attribute(cp, configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_VERSION, val1));
//    chunk_t val2 = chunk_from_chars('0','0','-','5','0','-','5','6','-','8','9','-');
//    cp->add_attribute(cp, configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_REGISTRATION_ID, val2));
//    uint8_t raw3[] = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x23, 0xfb }; // 000500000023fb
//    chunk_t val3 = chunk_create(raw3, sizeof(raw3));
//    cp->add_attribute(cp, configuration_attribute_create_chunk(PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_CLIENT_RELEASE_ID, val3));
//
//    cp->set_identifier(cp, this->identifier);
//    message->add_payload(message, (payload_t*)cp);
//
//    return SUCCESS;
//}

static status_t sonicwall_build_reply(private_mode_config_t *this, message_t *message)
{
    cp_payload_t *cp;

    cp = cp_payload_create_type(PLV1_CONFIGURATION, ISAKMP_SW_POLICY_VERSION_REPLY);

    chunk_t address = chunk_empty;
    address.ptr = "0.0.0.0";
    address.len = 20;
    cp->add_attribute(cp, configuration_attribute_create_chunk(
            PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_VERSION, address));

    chunk_t address1 = chunk_empty;
    address1.ptr = "255.255.255.255";
    address1.len = 12;
    cp->add_attribute(cp, configuration_attribute_create_chunk(
            PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_REGISTRATION_ID, address1));

    chunk_t address2 = chunk_empty;
    address2.ptr = "192.168.168.168";
    address2.len = 8;
    cp->add_attribute(cp, configuration_attribute_create_chunk(
            PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_CLIENT_RELEASE_ID, address2));

    chunk_t address3 = chunk_empty;
    address3.ptr = "0.0.0.0";
    address3.len = 8;
    cp->add_attribute(cp, configuration_attribute_create_chunk(
            PLV1_CONFIGURATION_ATTRIBUTE, ISAKMP_MODECFG_ATTRIB_SONICWALL_POLICY_CLIENT_RELEASE_ID, address2));

    cp->set_identifier(cp, this->identifier);
    message->add_payload(message, (payload_t*)cp);

    return SUCCESS;
}

METHOD(task_t, build_r, status_t,
	private_mode_config_t *this, message_t *message)
{
	if (this->pull)
	{
		//return build_reply(this, message);
        return sonicwall_build_reply(this, message);
	}

	return sonicwall_build_ack(this, message);


}

METHOD(task_t, process_i, status_t,
	private_mode_config_t *this, message_t *message)
{
	process_payloads(this, message);

	if (this->pull)
	{
		install_vips(this);
	}
	return SUCCESS;
}

METHOD(task_t, get_type, task_type_t,
	private_mode_config_t *this)
{
	return TASK_MODE_CONFIG;
}

METHOD(task_t, migrate, void,
	private_mode_config_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
	this->vips->destroy_offset(this->vips, offsetof(host_t, destroy));
	this->vips = linked_list_create();
	this->attributes->destroy_function(this->attributes, free);
	this->attributes = linked_list_create();
}

METHOD(task_t, destroy, void,
	private_mode_config_t *this)
{
	this->vips->destroy_offset(this->vips, offsetof(host_t, destroy));
	this->attributes->destroy_function(this->attributes, free);
	free(this);
}

/*
 * Described in header.
 */
mode_config_t *mode_config_create(ike_sa_t *ike_sa, bool initiator, bool pull)
{
	private_mode_config_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.initiator = initiator,
		.pull = initiator ? pull : TRUE,
		.ike_sa = ike_sa,
		.attributes = linked_list_create(),
		.vips = linked_list_create(),
	);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}

	return &this->public;
}
