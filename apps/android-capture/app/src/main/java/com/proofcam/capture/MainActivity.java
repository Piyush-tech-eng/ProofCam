package com.proofcam.capture;

import android.Manifest;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.ComponentActivity;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageCapture;
import androidx.camera.core.ImageCaptureException;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.common.util.concurrent.ListenableFuture;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Native CameraX capture -> exact file hash -> Keystore signature -> API validation.
 * The POC's API stores the registration in its local demo registry, not Solana.
 */
public final class MainActivity extends ComponentActivity {
    private static final int CAMERA_PERMISSION = 41;
    // Emulator default. For a physical phone, replace with the developer machine's LAN API URL.
    private static final String API_BASE = "http://10.0.2.2:3000";
    private static final String KEY_ALIAS = "proofcam-capture-p256-v1";

    private final ExecutorService background = Executors.newSingleThreadExecutor();
    private PreviewView previewView;
    private TextView statusView;
    private Button captureButton;
    private ImageCapture imageCapture;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        buildUi();
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera();
        } else {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.CAMERA}, CAMERA_PERMISSION);
        }
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.rgb(16, 26, 36));

        TextView title = new TextView(this);
        title.setText("ProofCam Capture");
        title.setTextColor(Color.WHITE);
        title.setTextSize(23);
        title.setPadding(20, 24, 20, 6);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Native camera · SHA-256 · Android Keystore");
        subtitle.setTextColor(Color.rgb(120, 220, 227));
        subtitle.setTextSize(13);
        subtitle.setPadding(20, 0, 20, 16);
        root.addView(subtitle);

        previewView = new PreviewView(this);
        previewView.setImplementationMode(PreviewView.ImplementationMode.COMPATIBLE);
        root.addView(previewView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        captureButton = new Button(this);
        captureButton.setText("Capture and register");
        captureButton.setOnClickListener(view -> capture());
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        buttonParams.setMargins(20, 16, 20, 8);
        root.addView(captureButton, buttonParams);

        statusView = new TextView(this);
        statusView.setText("Local demo mode: no Solana transaction is created.");
        statusView.setTextColor(Color.rgb(190, 196, 192));
        statusView.setTextSize(12);
        statusView.setGravity(Gravity.CENTER_VERTICAL);
        statusView.setPadding(20, 8, 20, 20);
        root.addView(statusView);
        setContentView(root);
    }

    private void startCamera() {
        ListenableFuture<ProcessCameraProvider> future = ProcessCameraProvider.getInstance(this);
        future.addListener(() -> {
            try {
                ProcessCameraProvider provider = future.get();
                Preview preview = new Preview.Builder().build();
                preview.setSurfaceProvider(previewView.getSurfaceProvider());
                imageCapture = new ImageCapture.Builder()
                        .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                        .build();
                provider.unbindAll();
                provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, imageCapture);
                status("Camera ready. Location sharing is off.");
            } catch (Exception error) {
                status("Could not start the camera: " + error.getMessage());
            }
        }, ContextCompat.getMainExecutor(this));
    }

    private void capture() {
        if (imageCapture == null) { status("Camera is not ready yet."); return; }
        captureButton.setEnabled(false);
        status("Capturing exact JPEG bytes…");
        File pictures = getExternalFilesDir(android.os.Environment.DIRECTORY_PICTURES);
        if (pictures == null) pictures = getFilesDir();
        if (!pictures.exists() && !pictures.mkdirs()) {
            captureButton.setEnabled(true);
            status("Could not create the private capture folder.");
            return;
        }
        File image = new File(pictures, "capture-" + System.currentTimeMillis() + ".jpg");
        ImageCapture.OutputFileOptions options = new ImageCapture.OutputFileOptions.Builder(image).build();
        imageCapture.takePicture(options, ContextCompat.getMainExecutor(this), new ImageCapture.OnImageSavedCallback() {
            @Override public void onImageSaved(ImageCapture.OutputFileResults result) {
                status("Image captured. Signing package and validating with the API…");
                background.execute(() -> registerCapture(image));
            }
            @Override public void onError(ImageCaptureException exception) {
                captureButton.setEnabled(true);
                status("Capture failed: " + exception.getMessage());
            }
        });
    }

    private void registerCapture(File image) {
        try {
            byte[] imageBytes = readFileBytes(image);
            String imageHash = hex(MessageDigest.getInstance("SHA-256").digest(imageBytes));
            JSONObject challenge = post("/v1/captures/challenge", new JSONObject());
            String nonce = challenge.getString("nonce");

            KeyPair keyPair = loadOrCreateKey();
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            String keyId = hex(MessageDigest.getInstance("SHA-256").digest(publicKeyBytes));
            byte[] idBytes = new byte[32];
            new SecureRandom().nextBytes(idBytes);
            String captureId = hex(idBytes);

            JSONObject location = new JSONObject();
            location.put("shared", false);
            location.put("geohash", JSONObject.NULL);
            JSONObject payload = new JSONObject();
            payload.put("schema_version", "1");
            payload.put("capture_id", captureId);
            payload.put("image_sha256", imageHash);
            payload.put("capture_method", "native_camera");
            payload.put("captured_at_device", captureTimestamp());
            payload.put("device_key_id", keyId);
            payload.put("challenge_nonce", nonce);
            payload.put("app_version", "0.1.0");
            payload.put("location", location);

            byte[] signedBytes = canonical(payload).getBytes(StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(signedBytes);
            String signature = Base64.encodeToString(signer.sign(), Base64.NO_WRAP);

            JSONObject capturePackage = new JSONObject();
            capturePackage.put("schema_version", "1");
            capturePackage.put("payload", payload);
            capturePackage.put("signature", signature);
            capturePackage.put("signature_algorithm", "SHA256withECDSA");
            capturePackage.put("public_key", Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP));
            capturePackage.put("key_id", keyId);
            capturePackage.put("attestation_chain_ref", JSONObject.NULL);
            capturePackage.put("api_validation_ref", JSONObject.NULL);

            JSONObject validationBody = new JSONObject();
            validationBody.put("package", capturePackage);
            JSONObject validation = post("/v1/captures/validate", validationBody);
            JSONObject registrationBody = new JSONObject();
            registrationBody.put("capture_id", captureId);
            registrationBody.put("manifest_cid", validation.getString("manifest_cid"));
            registrationBody.put("authority", "android-keystore-demo");
            JSONObject registration = post("/v1/captures/index", registrationBody);

            JSONObject record = registration.getJSONObject("record");
            runOnUiThread(() -> {
                captureButton.setEnabled(true);
                status("Local demo record created.\nCapture ID: " + captureId
                        + "\nSHA-256: " + imageHash
                        + "\nManifest: " + validation.optString("manifest_cid")
                        + "\n" + registration.optString("warning"));
            });
        } catch (Exception error) {
            runOnUiThread(() -> {
                captureButton.setEnabled(true);
                status("Registration failed: " + error.getMessage());
            });
        }
    }

    private KeyPair loadOrCreateKey() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(KEY_ALIAS)) {
            java.security.PrivateKey privateKey = (java.security.PrivateKey) store.getKey(KEY_ALIAS, null);
            java.security.PublicKey publicKey = store.getCertificate(KEY_ALIAS).getPublicKey();
            return new KeyPair(publicKey, privateKey);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        generator.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build());
        return generator.generateKeyPair();
    }

    private JSONObject post(String path, JSONObject body) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(API_BASE + path).openConnection();
        connection.setRequestMethod("POST");
        connection.setConnectTimeout(8000);
        connection.setReadTimeout(12000);
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        try (OutputStream output = connection.getOutputStream()) {
            output.write(body.toString().getBytes(StandardCharsets.UTF_8));
        }
        int statusCode = connection.getResponseCode();
        InputStream stream = statusCode < 400 ? connection.getInputStream() : connection.getErrorStream();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.read(buffer)) >= 0) bytes.write(buffer, 0, count);
        connection.disconnect();
        JSONObject response = new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
        if (statusCode >= 400) throw new IllegalStateException(response.optString("message", "API error " + statusCode));
        return response;
    }

    private static String canonical(Object value) throws Exception {
        if (value == JSONObject.NULL || value == null) return "null";
        if (value instanceof String) return JSONObject.quote((String) value);
        if (value instanceof Boolean || value instanceof Number) return value.toString();
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value;
            List<String> keys = new ArrayList<>();
            Iterator<String> iterator = object.keys();
            while (iterator.hasNext()) keys.add(iterator.next());
            Collections.sort(keys);
            List<String> pairs = new ArrayList<>();
            for (String key : keys) pairs.add(JSONObject.quote(key) + ":" + canonical(object.get(key)));
            return "{" + joinValues(pairs) + "}";
        }
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            List<String> values = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) values.add(canonical(array.get(i)));
            return "[" + joinValues(values) + "]";
        }
        throw new IllegalArgumentException("Unsupported value in signed payload");
    }

    private static byte[] readFileBytes(File file) throws Exception {
        try (InputStream input = new FileInputStream(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
            return output.toByteArray();
        }
    }

    private static String captureTimestamp() {
        java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US);
        format.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return format.format(new java.util.Date());
    }

    private static String joinValues(List<String> values) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) result.append(',');
            result.append(values.get(i));
        }
        return result.toString();
    }

    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte value : data) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
        return out.toString();
    }

    private void status(String text) { statusView.setText(text); }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == CAMERA_PERMISSION && results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) startCamera();
        else status("Camera permission is required to capture an image.");
    }

    @Override protected void onDestroy() {
        super.onDestroy();
        background.shutdown();
    }
}
