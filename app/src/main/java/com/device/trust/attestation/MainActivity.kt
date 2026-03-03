package com.device.trust.attestation

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.device.trust.attestation.checker.DeviceTrustChecker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnCheck = findViewById<Button>(R.id.btn_check_trust)
        val tvResult = findViewById<TextView>(R.id.tv_result)
        val checker = DeviceTrustChecker()

        btnCheck.setOnClickListener {
            tvResult.text = "校验中..."
            CoroutineScope(Dispatchers.IO).launch {
                val result = checker.checkDeviceTrust()
                withContext(Dispatchers.Main) {
                    tvResult.text = buildString {
                        append("===== 设备可信性校验结果 =====\n\n")
                        append("是否可信：${if (result.isTrusted) "✅ 是" else "❌ 否"}\n")
                        append("风险类型：${result.riskType.name}\n")
                        append("校验信息：${result.message}\n\n")
                        result.certificateSerial?.let { append("证书绑定序列号：$it") }
                    }
                    tvResult.setTextColor(
                        if (result.isTrusted) 0xFF00AA00.toInt() else 0xFFFF0000.toInt()
                    )
                }
            }
        }
    }
}
