package chatapp.android.net

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * Phase 4 — minimal JSON client for the vertical slice (design §3, Appendix B #1):
 * HttpURLConnection + built-in org.json, zero new dependencies.
 *
 * Security notes (user mandate #6/#10): this class never logs; it never persists
 * anything. Bodies/tokens flow only through the return values. A single retry on
 * transport (IOException) failures is performed; API errors (4xx/5xx) are thrown
 * as [ApiException] and never retried here.
 */
class ChatApiClient(baseUrl: String) {

    class ApiException(
        val status: Int,
        val code: String?,
        val correlationId: String?,
        bodySnippet: String?,
    ) : Exception("HTTP $status code=$code corr=$correlationId body=${bodySnippet?.take(200)}")

    private val baseUrl = baseUrl.trimEnd('/')
    private var correlationSeq = 0

    /**
     * Performs one HTTP request. Returns the parsed JSON object, or null for an
     * empty (204) body. Throws [ApiException] for any non-2xx response.
     */
    @Throws(IOException::class, ApiException::class)
    fun request(method: String, path: String, token: String? = null, body: JSONObject? = null): JSONObject? {
        correlationSeq += 1
        val corrId = "android-${System.currentTimeMillis().toString(36)}-$correlationSeq"
        var lastError: IOException? = null
        for (attempt in 1..2) {
            val conn = URL(baseUrl + path).openConnection() as HttpURLConnection
            try {
                conn.requestMethod = method
                conn.connectTimeout = 15_000
                conn.readTimeout = 15_000
                conn.setRequestProperty("x-correlation-id", "$corrId-$attempt")
                if (token != null) conn.setRequestProperty("authorization", "Bearer $token")
                val payload = body?.toString()?.toByteArray(Charsets.UTF_8)
                if (payload != null) {
                    conn.doOutput = true
                    conn.setRequestProperty("content-type", "application/json")
                    conn.fixedLengthStreamingMode(payload.size)
                    conn.outputStream.use { it.write(payload) }
                }
                val status = conn.responseCode
                val stream = if (status in 200..299) conn.inputStream else conn.errorStream
                val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
                val respCorr = conn.getHeaderField("x-correlation-id")
                if (status in 200..299) {
                    return if (text.isBlank()) null else JSONObject(text)
                }
                val json = if (text.isBlank()) null else runCatching { JSONObject(text) }.getOrNull()
                throw ApiException(
                    status,
                    json?.optJSONObject("error")?.optString("code"),
                    respCorr,
                    text,
                )
            } catch (e: IOException) {
                lastError = e
                if (attempt == 2) throw e
            } finally {
                conn.disconnect()
            }
        }
        throw lastError ?: IOException("request failed: $method $path")
    }
}
