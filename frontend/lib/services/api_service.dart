import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiService {
  // ── Change this to your backend URL ──
  // Android Emulator:     http://10.0.2.2:8000
  // iOS Simulator:        http://localhost:8000
  // Physical device:      http://<your-laptop-ip>:8000
  // Web:                  http://localhost:8000
  static const String baseUrl = "http://127.0.0.1:8000";

  static Future<Map<String, dynamic>> analyzeQr(String content) async {
    final url = Uri.parse("$baseUrl/api/analyze");
    final response = await http
        .post(url,
          headers: {"Content-Type": "application/json"},
          body: jsonEncode({"content": content}))
        .timeout(const Duration(seconds: 15));

    if (response.statusCode == 200) {
      return jsonDecode(response.body);
    } else {
      throw Exception("Backend error: ${response.statusCode} – ${response.body}");
    }
  }

  static Future<bool> healthCheck() async {
    try {
      final url = Uri.parse("$baseUrl/health");
      final response = await http.get(url).timeout(const Duration(seconds: 5));
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }
}
