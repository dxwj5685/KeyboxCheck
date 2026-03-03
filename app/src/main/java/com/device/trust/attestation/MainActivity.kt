package com.device.trust.attestation
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.device.trust.attestation.checker.DeviceTrustChecker
import com.device.trust.attestation.model.RiskType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val checker = DeviceTrustChecker(this)

        val btn = findViewById<Button>(R.id.btn_check_trust)
        val tv = findViewById<TextView>(R.id.tv_result)

        btn.setOnClickListener {
            tv.text = "校验中..."
            CoroutineScope(Dispatchers.IO).launch {
                val r = checker.check()
                withContext(Dispatchers.Main) {
                    tv.text = buildString {
                        append("可信：${if (r.isTrusted) "✅ 是" else "❌ 否"}\n")
                        append("结果：${r.riskType}\n")
                        append("信息：${r.message}\n")
                        r.deviceSerial?.let { append("设备SN：$it\n") }
                        r.certificateSerial?.let { append("证书SN：$it") }
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
