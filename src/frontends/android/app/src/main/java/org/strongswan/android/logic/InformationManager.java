package org.strongswan.android.logic;// In a suitable class, e.g., VpnProfileControlActivity.java or a new JniBridge.java
// This class needs access to an application Context.

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import androidx.appcompat.app.AlertDialog;
import org.strongswan.android.R;
import org.strongswan.android.ui.MainActivity;
import java.util.concurrent.CountDownLatch;


public class InformationManager {
	private static Context myActivity;
	private static MainActivity mMainActivity;
	private static final String TAG = "InformationManager";

	// Call this once when your application starts to provide context
	public static void initialize(Context context) {
		myActivity = context;
		mMainActivity = (MainActivity)context;
	}

	public InformationManager(Context context) {
	}

	/**
	 * This method is called FROM the native C code via JNI.
	 * It displays a password dialog on the UI thread and blocks the calling
	 * native thread until the user provides input.
	 *
	 * @param label The title/message for the dialog (e.g., "XAuth Password").
	 * @return The entered password, or null if the user cancels.
	 */
	public static String requestPasswordFromUi(final String label) {
		if (myActivity == null) {
			return null;
		}

		final CountDownLatch latch = new CountDownLatch(1);
		final String[] result = new String[1];

		// Post a task to the main UI thread to show the dialog.
		new Handler(Looper.getMainLooper()).post(() -> {

			LayoutInflater inflater = mMainActivity.getLayoutInflater();
			View view = inflater.inflate(R.layout.information_dialog, null);
			final EditText password = view.findViewById(R.id.password);

			new AlertDialog.Builder(myActivity)
				.setTitle("Authentication Required")
				.setMessage(label)
				.setView(view)
				.setPositiveButton(android.R.string.ok, (dialog, which) -> {
					result[0] = password.getText().toString().trim();
					latch.countDown(); // Release the waiting native thread
				})
				.setNegativeButton(android.R.string.cancel, (dialog, which) -> {
					result[0] = null;
					dialog.cancel();
					latch.countDown(); // Also release on cancel
				})
				.setOnCancelListener(dialog -> {
					result[0] = null;
					latch.countDown(); // Also release on dialog cancellation
				})
				.show();
		});

		try {
			latch.await();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return null; // Return null if interrupted
		}

		return result[0];
	}
}
