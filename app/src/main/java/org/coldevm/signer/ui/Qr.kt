package org.coldevm.signer.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.camera.core.Camera
import androidx.compose.foundation.clickable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.sparrowwallet.hummingbird.UR
import com.sparrowwallet.hummingbird.URDecoder
import com.sparrowwallet.hummingbird.UREncoder
import kotlinx.coroutines.delay
import java.util.concurrent.Executors

fun qrBitmap(text: String): Bitmap {
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(
        EncodeHintType.MARGIN to 2,
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
    ))
    val bmp = Bitmap.createBitmap(matrix.width, matrix.height, Bitmap.Config.ARGB_8888)
    for (y in 0 until matrix.height) for (x in 0 until matrix.width) {
        bmp.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
    }
    return bmp
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

/** Full brightness and no screen timeout while a QR is on screen, restored afterwards. */
@Composable
private fun BrightScreen() {
    val window = LocalContext.current.findActivity()?.window ?: return
    DisposableEffect(window) {
        val previous = window.attributes.screenBrightness
        window.attributes = window.attributes.apply { screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL }
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        onDispose {
            window.attributes = window.attributes.apply { screenBrightness = previous }
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }
}

/** Shows a UR as a single QR or, when it does not fit, as a looping animated (fountain-coded) QR. Tap to slow down. */
@Composable
fun AnimatedUrQr(ur: UR, modifier: Modifier = Modifier, fragmentLen: Int = 200) {
    BrightScreen()
    val encoder = remember(ur) { UREncoder(ur, fragmentLen, 10, 0) }
    var bitmap by remember(ur) { mutableStateOf(qrBitmap(encoder.nextPart().uppercase())) }
    var slow by remember { mutableStateOf(false) }
    LaunchedEffect(ur, slow) {
        if (encoder.isSinglePart) return@LaunchedEffect
        while (true) {
            delay(if (slow) 700 else 250)
            bitmap = qrBitmap(encoder.nextPart().uppercase())
        }
    }
    Column {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "QR",
            filterQuality = FilterQuality.None,
            contentScale = ContentScale.Fit,
            modifier = modifier.fillMaxWidth().aspectRatio(1f).background(Color.White).clickable { slow = !slow },
        )
        if (!encoder.isSinglePart) {
            Text(if (slow) "慢速播放中 · 点击二维码恢复正常速度" else "扫不出来？点击二维码放慢速度", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 6.dp))
        }
    }
}

/** A plain single-frame QR, e.g. an address for the online phone to scan and compare. */
@Composable
fun StaticQr(text: String, modifier: Modifier = Modifier) {
    BrightScreen()
    val bitmap = remember(text) { qrBitmap(text) }
    Image(
        bitmap = bitmap.asImageBitmap(),
        contentDescription = "QR",
        filterQuality = FilterQuality.None,
        contentScale = ContentScale.Fit,
        modifier = modifier.fillMaxWidth().aspectRatio(1f).background(Color.White),
    )
}

/** Camera scanner that feeds every QR it sees into a BC-UR decoder until a full UR is assembled. */
@Composable
fun UrScanner(onResult: (UR) -> Unit, onError: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    LaunchedEffect(Unit) { if (!granted) launcher.launch(Manifest.permission.CAMERA) }
    if (!granted) {
        Text("需要相机权限才能扫描二维码", modifier = Modifier.padding(16.dp))
        return
    }

    var progress by remember { mutableStateOf(0.0) }
    var hint by remember { mutableStateOf<String?>(null) }
    var camera by remember { mutableStateOf<Camera?>(null) }
    var torch by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf(false) }
    val decoder = remember { URDecoder() }
    val executor = remember { Executors.newSingleThreadExecutor() }
    var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    DisposableEffect(Unit) {
        onDispose {
            cameraProvider?.unbindAll()
            executor.shutdown()
        }
    }

    Column {
        AndroidView(
            modifier = Modifier.fillMaxWidth().aspectRatio(1f).clipToBounds(),
            factory = { ctx ->
                // TextureView-backed preview: a SurfaceView ignores Compose clipping and scrolling.
                val view = PreviewView(ctx).apply { implementationMode = PreviewView.ImplementationMode.COMPATIBLE }
                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                providerFuture.addListener({
                    if (executor.isShutdown) return@addListener
                    val provider = providerFuture.get()
                    cameraProvider = provider
                    val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                    val reader = MultiFormatReader().apply {
                        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
                    }
                    // The default 640x480 analysis frames are too coarse for dense animated QRs; 720p decodes them reliably.
                    val resolution = ResolutionSelector.Builder()
                        .setResolutionStrategy(ResolutionStrategy(android.util.Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER))
                        .build()
                    val analysis = ImageAnalysis.Builder()
                        .setResolutionSelector(resolution)
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                    analysis.setAnalyzer(executor) { image ->
                        try {
                            val plane = image.planes[0]
                            val w = image.width; val h = image.height
                            val buf = plane.buffer
                            val y = ByteArray(w * h)
                            for (row in 0 until h) {
                                buf.position(row * plane.rowStride)
                                buf.get(y, row * w, w)
                            }
                            val text = try {
                                reader.decodeWithState(BinaryBitmap(HybridBinarizer(PlanarYUVLuminanceSource(y, w, h, 0, 0, w, h, false)))).text
                            } catch (_: NotFoundException) { null } finally { reader.reset() }
                            if (text != null) {
                                ContextCompat.getMainExecutor(ctx).execute {
                                    if (done) return@execute
                                    if (!text.lowercase().startsWith("ur:")) {
                                        hint = "这不是 OKX Wallet 的签名二维码，请对准 OKX 显示的动态二维码"
                                        return@execute
                                    }
                                    hint = null
                                    // Hostile frames must not crash the app: drop the frame and keep scanning.
                                    try { decoder.receivePart(text.lowercase()) } catch (_: Exception) { return@execute } catch (_: OutOfMemoryError) { return@execute }
                                    progress = decoder.estimatedPercentComplete
                                    val result = decoder.result
                                    if (result != null) {
                                        done = true
                                        if (result.type == com.sparrowwallet.hummingbird.ResultType.SUCCESS) onResult(result.ur)
                                        else onError(result.error ?: "二维码解码失败")
                                    }
                                }
                            }
                        } catch (_: Exception) {
                        } finally {
                            image.close()
                        }
                    }
                    provider.unbindAll()
                    camera = provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                }, ContextCompat.getMainExecutor(ctx))
                view
            },
        )
        LinearProgressIndicator(progress = { progress.toFloat() }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        Text(
            if (progress > 0) "已接收 ${(progress * 100).toInt()}%，请保持对准动态二维码" else "将相机对准 OKX Wallet 显示的二维码",
            modifier = Modifier.padding(top = 8.dp),
        )
        hint?.let { Text(it, color = WarnColor, modifier = Modifier.padding(top = 4.dp)) }
        if (camera?.cameraInfo?.hasFlashUnit() == true) {
            OutlinedButton(onClick = { torch = !torch; camera?.cameraControl?.enableTorch(torch) }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                Text(if (torch) "关闭手电筒" else "打开手电筒")
            }
        }
    }
}
