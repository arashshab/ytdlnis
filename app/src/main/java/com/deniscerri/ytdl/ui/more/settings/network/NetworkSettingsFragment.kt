package com.deniscerri.ytdl.ui.more.settings.network

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.preference.EditTextPreference
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceManager
import androidx.preference.SwitchPreferenceCompat
import com.deniscerri.ytdl.R
import com.deniscerri.ytdl.ui.more.settings.BaseSettingsFragment
import com.deniscerri.ytdl.util.DomainFrontingManager

class NetworkSettingsFragment : BaseSettingsFragment() {

    override val title: Int = R.string.network_settings

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.network_preferences, rootKey)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val prefs = PreferenceManager.getDefaultSharedPreferences(requireContext())

        // سوئیچ فعال/غیرفعال کردن
        val enableSwitch = findPreference<SwitchPreferenceCompat>(DomainFrontingManager.PREF_ENABLED)

        // انتخاب پروفایل
        val profileList = findPreference<ListPreference>(DomainFrontingManager.PREF_PROFILE)

        // تنظیمات Custom
        val customFront = findPreference<EditTextPreference>(DomainFrontingManager.PREF_CUSTOM_FRONT)
        val customTarget = findPreference<EditTextPreference>(DomainFrontingManager.PREF_CUSTOM_TARGET)
        val customIp = findPreference<EditTextPreference>(DomainFrontingManager.PREF_CUSTOM_IP)

        // دکمه تست اتصال
        val testBtn = findPreference<Preference>("domain_fronting_test")

        // نمایش/مخفی کردن Custom fields
        fun updateCustomVisibility() {
            val isCustom = profileList?.value == "custom"
            customFront?.isVisible = isCustom
            customTarget?.isVisible = isCustom
            customIp?.isVisible = isCustom
        }

        // نمایش/مخفی کردن همه تنظیمات
        fun updateAllVisibility() {
            val enabled = enableSwitch?.isChecked ?: false
            profileList?.isVisible = enabled
            testBtn?.isVisible = enabled
            updateCustomVisibility()
            if (!enabled) {
                customFront?.isVisible = false
                customTarget?.isVisible = false
                customIp?.isVisible = false
            }
        }

        updateAllVisibility()

        enableSwitch?.setOnPreferenceChangeListener { _, newValue ->
            val enabled = newValue as Boolean
            if (enabled) {
                Toast.makeText(
                    requireContext(),
                    "Domain Fronting فعال شد ✓",
                    Toast.LENGTH_SHORT
                ).show()
            }
            updateAllVisibility()
            true
        }

        profileList?.setOnPreferenceChangeListener { _, _ ->
            updateCustomVisibility()
            true
        }

        // تست اتصال
        testBtn?.setOnPreferenceClickListener {
            testConnection(prefs)
            true
        }
    }

    private fun testConnection(prefs: android.content.SharedPreferences) {
        val config = DomainFrontingManager.loadConfig(prefs)
        if (!config.enabled) {
            Toast.makeText(requireContext(), "ابتدا Domain Fronting را فعال کنید", Toast.LENGTH_SHORT).show()
            return
        }

        Toast.makeText(requireContext(), "در حال تست اتصال...", Toast.LENGTH_SHORT).show()

        Thread {
            try {
                val client = DomainFrontingManager.buildClient(requireContext())
                val request = okhttp3.Request.Builder()
                    .url("https://www.googleapis.com/")
                    .build()
                val response = client.newCall(request).execute()
                val success = response.code < 500
                response.close()

                requireActivity().runOnUiThread {
                    val msg = if (success) "✓ اتصال موفق! (${response.code})" else "✗ خطا: ${response.code}"
                    Toast.makeText(requireContext(), msg, Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                requireActivity().runOnUiThread {
                    Toast.makeText(requireContext(), "✗ خطا: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }
}
