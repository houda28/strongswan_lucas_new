# Container for building OpenSSL's libcrypto for use in strongSwan's Android app
#
# Use the script to simplify the process of building the image and running
# the compilation in the container, e.g.:
#
#   ANDROID_NDK_ROOT=~/android-ndk OPENSSL_SRC=~/openssl ./build.sh

FROM debian:bullseye

ARG packages="jq make perl"

ENV HTTP_PROXY=http://10.50.128.110:3128
ENV HTTPS_PROXY=http://10.50.128.110:3128

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
  --no-install-recommends \
  $packages \
  && rm -rf /var/lib/apt/lists/*

COPY compile.sh /
RUN chmod +x /compile.sh



ENV ANDROID_NDK_ROOT /ndk
#ENV ANDROID_NDK_ROOT /Users/hshu/Library/Android/sdk/ndk/22.1.7171670


ENV OUT_DIR /out

WORKDIR /src

ENTRYPOINT ["/compile.sh"]
