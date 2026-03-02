package com.keyboxchecker.demo

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.keyboxchecker.demo.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val REQUEST_PHONE_PERMISSION = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // 点击按钮触发检测
        binding.btnCheck.setOnClickListener {
            checkPermissionAndStartValidation()
        }
    }

    /**
     * 先申请权限，再执行校验
     */
    private fun checkPermissionAndStartValidation() {
        val requiredPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.READ_PHONE_NUMBERS
        } else {
            Manifest.permission.READ_PHONE_STATE
        }

        if (ContextCompat.checkSelfPermission(this, requiredPermission)
            != PackageManager.PERMISSION_GRANTED
        ) {
            // 申请权限
            ActivityCompat.requestPermissions(
                this,
                arrayOf(requiredPermission),
                REQUEST_PHONE_PERMISSION
            )
            return
        }

        // 权限已获取，执行校验
        startKeyboxCheck()
    }

    /**
     * 执行核心校验并展示结果
     */
    private fun startKeyboxCheck() {
        binding.btnCheck.isEnabled = false
        binding.tvResult.text = "正在检测...\n请稍候（硬件加密操作可能耗时1-2秒）"

        // 子线程执行校验（避免主线程阻塞）
        Thread {
            // 获取本机真实Serial
            val deviceSerial = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    Build.getSerial()
                } else {
                    @Suppress("DEPRECATION")
                    Build.SERIAL
                }
            } catch (e: Exception) {
                "获取失败（权限不足/设备限制）"
            }

            // 执行校验
            val result = KeyboxSecurityValidator.checkFactoryKeybox(deviceSerial)

            // 主线程更新UI
            runOnUiThread {
                binding.btnCheck.isEnabled = true
                // 拼接日志为字符串
                val logText = result.log.joinToString("\n")
                binding.tvResult.text = logText

                // 弹出提示
                Toast.makeText(
                    this,
                    if (result.isFactoryKeybox) "设备安全" else "检测到风险Keybox",
                    Toast.LENGTH_LONG
                ).show()
            }
        }.start()
    }

    /**
     * 权限申请回调
     */
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_PHONE_PERMISSION) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startKeyboxCheck()
            } else {
                Toast.makeText(this, "需要权限才能获取设备Serial，检测终止", Toast.LENGTH_SHORT).show()
                binding.tvResult.text = "❌ 权限被拒绝，无法完成检测"
            }
        }
    }
}
