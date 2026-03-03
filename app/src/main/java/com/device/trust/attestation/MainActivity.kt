package com.device.trust.attestation

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.device.trust.attestation.checker.DeviceTrustChecker
import com.device.trust.attestation.model.RiskType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    companion object {
        private const val PERMISSION_REQUEST_CODE = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        // 【修复】移除了this参数，和DeviceTrustChecker的空构造函数完全匹配
        val checker = DeviceTrustChecker()

        val btn = findViewById<Button>(R.id.btn_check_trust)
        val tv = findViewById<TextView>(R.id.tv_result)

        btn.setOnClickListener {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                tv.text = "仅支持Android 8.0+设备"
                return@setOnClickListener
            }
            // 检查权限
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.READ_PHONE_STATE
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.READ_PHONE_STATE),
                    PERMISSION_REQUEST_CODE
                )
            } else {
                tv.text = "校验中..."
                CoroutineScope(Dispatchers.IO).launch {
                    val r = checker.check()
                    withContext(Dispatchers.Main) {
                        tv.text = buildString {
                            append("===== 设备可信性校验结果 =====\n")
                            append("是否可信：${if (r.isTrusted) "✅ 是" else "❌ 否"}\n")
                            append("风险类型：${r.riskType.name}\n")
                            append("校验信息：${r.message}\n")
                            r.deviceSerial?.let { append("设备真实序列号：$it\n") }
                            r.certificateSerial?.let { append("证书绑定序列号：$it") }
                        }
                        tv.setTextColor(
                            if (r.riskType == RiskType.TRUSTED) 0xFF00AA00.toInt()
                            else 0xFFFF0000.toInt()
                        )
                    }
                }
            }
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        val tv = findViewById<TextView>(R.id.tv_result)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                tv.text = "权限已授予，请重新点击校验按钮"
            } else {
                tv.text = "权限被拒绝，无法完成设备可信性校验"
            }
        }
    }
}
