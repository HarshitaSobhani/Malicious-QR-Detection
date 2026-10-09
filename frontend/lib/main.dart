import 'dart:io' show Platform;
import 'services/api_service.dart';
import 'dart:math';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';
import 'dart:convert';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    statusBarIconBrightness: Brightness.light,
  ));
  runApp(const SmartQRApp());
}

const demoUsername = 'hash';
const demoPassword = '1234';

// ══════════════════════════════════════════════════════════════════════
// Theme & Colors
// ══════════════════════════════════════════════════════════════════════
class AppColors {
  static const navy = Color(0xFF0F2B46);
  static const navyLight = Color(0xFF1B3F5E);
  static const accent = Color(0xFF00C9A7);    // teal-green accent
  static const accentLight = Color(0xFF00E4BD);
  static const surface = Color(0xFFF7F9FC);
  static const cardBg = Color(0xFFFFFFFF);
  static const textPrimary = Color(0xFF1A2B3C);
  static const textSecondary = Color(0xFF6B7C8D);
  static const safe = Color(0xFF00C853);
  static const safeLight = Color(0xFFE8F5E9);
  static const suspicious = Color(0xFFFF9100);
  static const suspiciousLight = Color(0xFFFFF3E0);
  static const dangerous = Color(0xFFFF1744);
  static const dangerousLight = Color(0xFFFFEBEE);
}

class SmartQRApp extends StatelessWidget {
  const SmartQRApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'QR Sentinel',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        scaffoldBackgroundColor: AppColors.surface,
        fontFamily: 'SF Pro Display',
        colorSchemeSeed: AppColors.navy,
        appBarTheme: const AppBarTheme(
          backgroundColor: AppColors.navy,
          foregroundColor: Colors.white,
          elevation: 0,
          centerTitle: true,
        ),
      ),
      routes: {
        '/': (_) => const Gate(),
        '/login': (_) => const LoginPage(),
        '/signup': (_) => const SignupPage(),
        '/scanner': (_) => const ScannerPage(),
      },
    );
  }
}

// ══════════════════════════════════════════════════════════════════════
// Gate
// ══════════════════════════════════════════════════════════════════════
class Gate extends StatefulWidget {
  const Gate({super.key});
  @override
  State<Gate> createState() => _GateState();
}

class _GateState extends State<Gate> {
  @override
  void initState() {
    super.initState();
    _check();
  }

  Future<void> _check() async {
    final prefs = await SharedPreferences.getInstance();
    final logged = prefs.getBool('logged_in') ?? false;
    if (!mounted) return;
    Navigator.of(context).pushReplacementNamed(logged ? '/scanner' : '/login');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.navy,
      body: Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          _buildLogo(64),
          const SizedBox(height: 16),
          const CircularProgressIndicator(color: AppColors.accent),
        ]),
      ),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════
// Splash / Login Page
// ══════════════════════════════════════════════════════════════════════
class LoginPage extends StatefulWidget {
  const LoginPage({super.key});
  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> with SingleTickerProviderStateMixin {
  final _form = GlobalKey<FormState>();
  String _user = '';
  String _pass = '';
  bool _loading = false;
  bool _obscure = true;
  String? _error;
  late AnimationController _fadeCtrl;
  late Animation<double> _fadeAnim;

  @override
  void initState() {
    super.initState();
    _fadeCtrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 800));
    _fadeAnim = CurvedAnimation(parent: _fadeCtrl, curve: Curves.easeOut);
    _fadeCtrl.forward();
  }

  @override
  void dispose() { _fadeCtrl.dispose(); super.dispose(); }

  Future<void> _doLogin() async {
    if (!_form.currentState!.validate()) return;
    setState(() { _loading = true; _error = null; });
    await Future.delayed(const Duration(milliseconds: 500));
    if (_user == demoUsername && _pass == demoPassword) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('logged_in', true);
      if (!mounted) return;
      Navigator.of(context).pushReplacementNamed('/scanner');
    } else {
      setState(() {
        _loading = false;
        _error = 'Invalid credentials (use: hash / 1234)';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [AppColors.navy, Color(0xFF0A1F33)],
          ),
        ),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 28),
              child: FadeTransition(
                opacity: _fadeAnim,
                child: Column(children: [
                  // Logo & branding
                  _buildLogo(56),
                  const SizedBox(height: 12),
                  const Text('QR Sentinel',
                    style: TextStyle(fontSize: 28, fontWeight: FontWeight.w700, color: Colors.white, letterSpacing: 0.5)),
                  const SizedBox(height: 6),
                  Text('Protect yourself from malicious QR codes',
                    style: TextStyle(fontSize: 14, color: Colors.white.withValues(alpha: 0.6))),
                  const SizedBox(height: 36),

                  // Login card
                  Container(
                    padding: const EdgeInsets.all(28),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(20),
                      boxShadow: [
                        BoxShadow(color: Colors.black.withValues(alpha: 0.15), blurRadius: 30, offset: const Offset(0, 10)),
                      ],
                    ),
                    child: Form(
                      key: _form,
                      child: Column(mainAxisSize: MainAxisSize.min, children: [
                        // Tab-like header
                        Row(children: [
                          _tabButton('Log in', true),
                          const SizedBox(width: 20),
                          GestureDetector(
                            onTap: () => Navigator.of(context).pushNamed('/signup'),
                            child: _tabButton('Sign up', false),
                          ),
                        ]),
                        const SizedBox(height: 24),

                        // Email
                        TextFormField(
                          decoration: _inputDecor('Email', Icons.mail_outline),
                          onChanged: (v) => _user = v.trim(),
                          validator: (v) => (v ?? '').isEmpty ? 'Enter username' : null,
                        ),
                        const SizedBox(height: 16),

                        // Password
                        TextFormField(
                          decoration: _inputDecor('Password', Icons.lock_outline).copyWith(
                            suffixIcon: IconButton(
                              icon: Icon(_obscure ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                                color: AppColors.textSecondary, size: 20),
                              onPressed: () => setState(() => _obscure = !_obscure),
                            ),
                          ),
                          obscureText: _obscure,
                          onChanged: (v) => _pass = v.trim(),
                          validator: (v) => (v ?? '').isEmpty ? 'Enter password' : null,
                        ),

                        // Forgot password
                        Align(
                          alignment: Alignment.centerRight,
                          child: TextButton(
                            onPressed: () {},
                            child: Text('Forgot password?', style: TextStyle(color: AppColors.accent, fontSize: 13)),
                          ),
                        ),

                        if (_error != null)
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                            margin: const EdgeInsets.only(bottom: 12),
                            decoration: BoxDecoration(
                              color: AppColors.dangerousLight,
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: Row(children: [
                              Icon(Icons.error_outline, size: 18, color: AppColors.dangerous),
                              const SizedBox(width: 8),
                              Expanded(child: Text(_error!, style: TextStyle(color: AppColors.dangerous, fontSize: 13))),
                            ]),
                          ),

                        // Login button
                        SizedBox(
                          width: double.infinity,
                          height: 52,
                          child: _loading
                              ? const Center(child: CircularProgressIndicator(color: AppColors.navy))
                              : ElevatedButton(
                                  onPressed: _doLogin,
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: AppColors.navy,
                                    foregroundColor: Colors.white,
                                    elevation: 0,
                                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                                  ),
                                  child: const Text('Log in', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                                ),
                        ),
                        const SizedBox(height: 16),
                        TextButton(
                          onPressed: () => Navigator.of(context).pushNamed('/signup'),
                          child: RichText(text: TextSpan(
                            style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
                            children: [
                              const TextSpan(text: "Don't have an account? "),
                              TextSpan(text: "Sign up", style: TextStyle(color: AppColors.accent, fontWeight: FontWeight.w600)),
                            ],
                          )),
                        ),
                      ]),
                    ),
                  ),

                  const SizedBox(height: 20),
                  Text('By continuing, you agree to our Terms of\nService and Privacy Policy',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 11, color: Colors.white.withValues(alpha: 0.4))),
                  const SizedBox(height: 24),
                ]),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _tabButton(String label, bool active) {
    return Column(children: [
      Text(label, style: TextStyle(
        fontSize: 16, fontWeight: FontWeight.w600,
        color: active ? AppColors.textPrimary : AppColors.textSecondary,
      )),
      const SizedBox(height: 4),
      Container(
        width: 40, height: 2.5,
        decoration: BoxDecoration(
          color: active ? AppColors.navy : Colors.transparent,
          borderRadius: BorderRadius.circular(2),
        ),
      ),
    ]);
  }

  InputDecoration _inputDecor(String label, IconData icon) {
    return InputDecoration(
      labelText: label,
      labelStyle: TextStyle(color: AppColors.textSecondary, fontSize: 14),
      prefixIcon: Icon(icon, color: AppColors.textSecondary, size: 20),
      filled: true,
      fillColor: AppColors.surface,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: BorderSide.none,
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: AppColors.navy, width: 1.5),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: AppColors.dangerous, width: 1),
      ),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════
// Signup Page
// ══════════════════════════════════════════════════════════════════════
class SignupPage extends StatelessWidget {
  const SignupPage({super.key});
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sign up')),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const Icon(Icons.info_outline, size: 48, color: AppColors.navy),
            const SizedBox(height: 16),
            const Text('Demo Mode', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            Text(
              'For this demo, use:\n\nUsername: hash\nPassword: 1234',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 15, color: AppColors.textSecondary, height: 1.5),
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: ElevatedButton(
                onPressed: () => Navigator.of(context).pop(),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.navy,
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                ),
                child: const Text('Back to Login'),
              ),
            ),
          ]),
        ),
      ),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════
// Scanner Page
// ══════════════════════════════════════════════════════════════════════
class ScannerPage extends StatefulWidget {
  const ScannerPage({super.key});
  @override
  State<ScannerPage> createState() => _ScannerPageState();
}

class _ScannerPageState extends State<ScannerPage> {
  final MobileScannerController _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.normal,
    facing: CameraFacing.back,
  );

  bool _analyzing = false;

  final demoSamples = <String>[
    "https://example.com/promo?ref=qr",
    "bit.ly/3XyzPhish",
    "http://xn--pple-43d.com/login",
    "http://192.168.1.50/download.apk",
    "Hello, this is plain text!",
    "upi://pay?pa=merchant@okbank&pn=Shop&aid=uGtCAgMc6KHaVA",
  ];

  @override
  void reassemble() {
    super.reassemble();
    if (!kIsWeb && Platform.isAndroid) _controller.stop();
    _controller.start();
  }

  Future<void> _handleScanned(String content) async {
    if (_analyzing) return;
    setState(() => _analyzing = true);
    await _controller.stop();

    try {
      final json = await ApiService.analyzeQr(content);
      final chainRaw = json["redirect_chain"] as List? ?? [];
      final chain = chainRaw
          .map((hop) => RedirectHop(
                url: hop["url"] ?? "", status: hop["status"] ?? 0, location: hop["location"],
              ))
          .toList();

      final result = AnalysisResult(
        type: json["content_type"] ?? "text",
        raw: content,
        finalUrl: json["final_url"],
        chain: chain,
        verdict: Verdict(
          json["verdict"]?.toString().toLowerCase() ?? "safe",
          (json["score"] as num?)?.toDouble() ?? 0.0,
        ),
        details: {
          "gsb": json["gsb_result"] ?? "n/a",
          "phishtank": json["phishtank_result"] ?? "n/a",
          "heuristics": json["heuristic_flags"] ?? [],
          "ml_score": json["ml_score"],
          "reasons": json["reasons"] ?? [],
        },
        scannedAt: json["scanned_at"] ?? DateTime.now().toIso8601String(),
      );

      if (!mounted) return;
await ScanHistory.save(result);
await Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => ResultPage(result: result, onLogout: _logout)),
      );
    } catch (e) {
      debugPrint("API error: $e");
      if (!mounted) return;
final result = await MockAnalyzer.analyze(content);
await ScanHistory.save(result);
await Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => ResultPage(result: result, onLogout: _logout)),
      );
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Row(children: [
            Icon(Icons.wifi_off, color: Colors.white, size: 18),
            SizedBox(width: 8),
            Text("Backend offline — used local analysis"),
          ]),
          backgroundColor: AppColors.suspicious,
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        ),
      );
    }

    setState(() => _analyzing = false);
    await _controller.start();
  }

  Future<void> _logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('logged_in', false);
    if (!mounted) return;
    Navigator.of(context).pushReplacementNamed('/login');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter, end: Alignment.bottomCenter,
            stops: [0.0, 0.35, 1.0],
            colors: [AppColors.navy, AppColors.navy, AppColors.surface],
          ),
        ),
        child: SafeArea(
          child: Column(children: [
            // App bar area
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Row(children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(Icons.shield_outlined, color: AppColors.accent, size: 22),
                ),
                const SizedBox(width: 10),
                const Expanded(
                  child: Text('QR Sentinel',
                    style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700, color: Colors.white)),
                ),
                _iconBtn(Icons.history_rounded, 'History', () {
  Navigator.of(context).push(
    MaterialPageRoute(builder: (_) => const HistoryPage()),
  );
}),
const SizedBox(width: 4),
                _iconBtn(Icons.bolt, 'Demo', () {
                  showModalBottomSheet(
                    context: context,
                    backgroundColor: Colors.transparent,
                    builder: (_) => _DemoSheet(samples: demoSamples, onSelect: _handleScanned),
                  );
                }),
                const SizedBox(width: 4),
                _iconBtn(Icons.logout_rounded, 'Logout', _logout),
              ]),
            ),

            const SizedBox(height: 12),

            // Scanner viewport
            Expanded(
              flex: 5,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(20),
                  child: Stack(children: [
                    MobileScanner(
                      controller: _controller,
                      onDetect: (capture) async {
                        if (_analyzing) return;
                        final codes = capture.barcodes;
                        if (codes.isEmpty) return;
                        await _handleScanned(codes.first.rawValue ?? '');
                      },
                    ),
                    // Scanner overlay corners
                    Positioned.fill(child: CustomPaint(painter: _ScannerOverlayPainter())),
                    // Analyzing overlay
                    if (_analyzing)
                      Positioned.fill(
                        child: Container(
                          color: Colors.black54,
                          child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                            const CircularProgressIndicator(color: AppColors.accent, strokeWidth: 3),
                            const SizedBox(height: 16),
                            const Text('Analyzing...', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w500)),
                          ]),
                        ),
                      ),
                  ]),
                ),
              ),
            ),

            // Bottom info panel
            Expanded(
              flex: 3,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(20, 20, 20, 8),
                child: Column(children: [
                  const Text('Scan QR Code',
                    style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700, color: AppColors.textPrimary)),
                  const SizedBox(height: 6),
                  Text('Point your camera at a QR code',
                    style: TextStyle(fontSize: 14, color: AppColors.textSecondary)),
                  const SizedBox(height: 16),

                  // Feature chips
                  Wrap(
                    spacing: 8, runSpacing: 8,
                    alignment: WrapAlignment.center,
                    children: [
                      _chip(Icons.link, 'Redirect Tracing'),
                      _chip(Icons.shield_outlined, 'Threat Detection'),
                      _chip(Icons.psychology_outlined, 'AI Analysis'),
                      _chip(Icons.lock_outline, 'Privacy First'),
                    ],
                  ),

                  const Spacer(),

                  // Info banner
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: AppColors.accent.withValues(alpha: 0.08),
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(color: AppColors.accent.withValues(alpha: 0.2)),
                    ),
                    child: Row(children: [
                      Container(
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(
                          color: AppColors.accent.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Icon(Icons.info_outline, color: AppColors.accent, size: 18),
                      ),
                      const SizedBox(width: 10),
                      const Expanded(
                        child: Text(
                          'QR Sentinel analyzes URLs for phishing, malware, and suspicious patterns before you open them.',
                          style: TextStyle(fontSize: 12, color: AppColors.textSecondary, height: 1.4),
                        ),
                      ),
                    ]),
                  ),
                  const SizedBox(height: 8),
                ]),
              ),
            ),
          ]),
        ),
      ),
    );
  }

  Widget _iconBtn(IconData icon, String tooltip, VoidCallback onTap) {
    return Tooltip(
      message: tooltip,
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Colors.white.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: Colors.white70, size: 20),
        ),
      ),
    );
  }

  Widget _chip(IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: AppColors.navy.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 14, color: AppColors.navy),
        const SizedBox(width: 5),
        Text(label, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w500, color: AppColors.navy)),
      ]),
    );
  }

  @override
  void dispose() { _controller.dispose(); super.dispose(); }
}

// Scanner corner overlay painter
class _ScannerOverlayPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = AppColors.accent
      ..strokeWidth = 3.5
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;

    const len = 30.0;
    const r = 12.0;

    // Top-left
    canvas.drawLine(const Offset(r, 0), Offset(len + r, 0), paint);
    canvas.drawLine(const Offset(0, r), Offset(0, len + r), paint);
    canvas.drawArc(const Rect.fromLTWH(0, 0, r * 2, r * 2), pi, pi / 2, false, paint);

    // Top-right
    canvas.drawLine(Offset(size.width - len - r, 0), Offset(size.width - r, 0), paint);
    canvas.drawLine(Offset(size.width, r), Offset(size.width, len + r), paint);
    canvas.drawArc(Rect.fromLTWH(size.width - r * 2, 0, r * 2, r * 2), -pi / 2, pi / 2, false, paint);

    // Bottom-left
    canvas.drawLine(Offset(r, size.height), Offset(len + r, size.height), paint);
    canvas.drawLine(Offset(0, size.height - len - r), Offset(0, size.height - r), paint);
    canvas.drawArc(Rect.fromLTWH(0, size.height - r * 2, r * 2, r * 2), pi / 2, pi / 2, false, paint);

    // Bottom-right
    canvas.drawLine(Offset(size.width - len - r, size.height), Offset(size.width - r, size.height), paint);
    canvas.drawLine(Offset(size.width, size.height - len - r), Offset(size.width, size.height - r), paint);
    canvas.drawArc(Rect.fromLTWH(size.width - r * 2, size.height - r * 2, r * 2, r * 2), 0, pi / 2, false, paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

// Demo samples bottom sheet
class _DemoSheet extends StatelessWidget {
  final List<String> samples;
  final Function(String) onSelect;
  const _DemoSheet({required this.samples, required this.onSelect});

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      padding: const EdgeInsets.fromLTRB(20, 12, 20, 24),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        Container(width: 40, height: 4, decoration: BoxDecoration(
          color: Colors.grey.shade300, borderRadius: BorderRadius.circular(2)),
        ),
        const SizedBox(height: 16),
        const Text('Demo Samples', style: TextStyle(fontSize: 17, fontWeight: FontWeight.w700)),
        const SizedBox(height: 4),
        Text('Tap a sample to simulate scanning', style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
        const SizedBox(height: 16),
        ...samples.map((s) => Padding(
          padding: const EdgeInsets.only(bottom: 6),
          child: ListTile(
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            tileColor: AppColors.surface,
            leading: Icon(
              s.startsWith('http') || s.contains('.') ? Icons.link : Icons.text_fields,
              color: AppColors.navy, size: 20,
            ),
            title: Text(s.length > 40 ? '${s.substring(0, 37)}...' : s,
              style: const TextStyle(fontSize: 13, fontFamily: 'monospace')),
            trailing: const Icon(Icons.arrow_forward_ios, size: 14, color: AppColors.textSecondary),
            onTap: () { Navigator.pop(context); onSelect(s); },
          ),
        )),
      ]),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════
// Data Models
// ══════════════════════════════════════════════════════════════════════
class Verdict {
  final String verdict;
  final double score;
  const Verdict(this.verdict, this.score);
}

class AnalysisResult {
  final String type;
  final String raw;
  final String? finalUrl;
  final List<RedirectHop> chain;
  final Verdict verdict;
  final Map<String, dynamic> details;
  final String scannedAt;
  const AnalysisResult({
    required this.type, required this.raw, required this.finalUrl,
    required this.chain, required this.verdict, required this.details, this.scannedAt = "",
  });
}

class RedirectHop {
  final String url;
  final int status;
  final String? location;
  const RedirectHop({required this.url, required this.status, this.location});
}

// ══════════════════════════════════════════════════════════════════════
// Mock Analyzer (fallback)
// ══════════════════════════════════════════════════════════════════════
class MockAnalyzer {
  static Future<AnalysisResult> analyze(String raw) async {
    await Future.delayed(const Duration(milliseconds: 400));
    final url = _extractUrl(raw);
    if (url == null) {
      return AnalysisResult(type: "text", raw: raw, finalUrl: null, chain: const [],
        verdict: const Verdict("safe", 0.0),
        details: {"heuristics": [], "reasons": ["Plain text - no URL detected"], "gsb": "offline", "phishtank": "offline", "ml_score": null});
    }
    final heur = <String>[];
    final uri = Uri.tryParse(url);
    final host = uri?.host ?? "";
    double score = 0;
    List<String> reasons = [];
    if (uri?.scheme == "http") { heur.add("Insecure Connection"); score = max(score, 0.1); reasons.add("Insecure Connection"); }
    if (RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(host)) { heur.add("IP Address URL"); score = max(score, 0.4); reasons.add("IP Address URL"); }
    if (host.startsWith("xn--")) { heur.add("Punycode/Homograph Domain"); score = max(score, 0.35); reasons.add("Punycode Domain"); }
    if (url.toLowerCase().endsWith(".apk")) { heur.add("APK Download Detected"); score = max(score, 0.65); reasons.add("APK Download"); }

    String label = score >= 0.7 ? "dangerous" : score >= 0.3 ? "suspicious" : "safe";
    return AnalysisResult(type: "url", raw: raw, finalUrl: url,
      chain: [RedirectHop(url: url, status: 200)],
      verdict: Verdict(label, double.parse(score.toStringAsFixed(2))),
      details: {"gsb": "offline", "phishtank": "offline", "heuristics": heur, "ml_score": null, "reasons": reasons},
      scannedAt: DateTime.now().toIso8601String());
  }

  static String? _extractUrl(String text) {
    final m = RegExp(r'(https?://[^\s]+)', caseSensitive: false).firstMatch(text);
    if (m != null) return m.group(1);
    final m2 = RegExp(r'((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(/\S*)?').firstMatch(text);
    if (m2 != null) return "http://${m2.group(0)}";
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════
// Scan History Storage
// ══════════════════════════════════════════════════════════════════════
class ScanHistory {
  static const _key = 'scan_history';

  static Future<List<Map<String, dynamic>>> load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    return raw.map((e) {
      try { return Map<String, dynamic>.from(jsonDecode(e)); }
      catch (_) { return <String, dynamic>{}; }
    }).where((m) => m.isNotEmpty).toList();
  }

  static Future<void> save(AnalysisResult r) async {
    final prefs = await SharedPreferences.getInstance();
    final list = prefs.getStringList(_key) ?? [];
    final entry = jsonEncode({
      'raw': r.raw,
      'finalUrl': r.finalUrl,
      'type': r.type,
      'verdict': r.verdict.verdict,
      'score': r.verdict.score,
      'scannedAt': r.scannedAt,
    });
    list.insert(0, entry);
    if (list.length > 100) list.removeRange(100, list.length);
    await prefs.setStringList(_key, list);
  }

  static Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }
}

// ══════════════════════════════════════════════════════════════════════
// History Page
// ══════════════════════════════════════════════════════════════════════
class HistoryPage extends StatefulWidget {
  const HistoryPage({super.key});
  @override
  State<HistoryPage> createState() => _HistoryPageState();
}

class _HistoryPageState extends State<HistoryPage> {
  List<Map<String, dynamic>> _records = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final data = await ScanHistory.load();
    setState(() { _records = data; _loading = false; });
  }

  Future<void> _clearAll() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Clear History'),
        content: const Text('Delete all scan records? This cannot be undone.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Clear', style: TextStyle(color: AppColors.dangerous)),
          ),
        ],
      ),
    );
    if (confirm == true) {
      await ScanHistory.clear();
      await _load();
    }
  }

  Color _verdictColor(String v) => switch (v) {
    "dangerous" => const Color.fromARGB(88, 255, 23, 69),
    "suspicious" => AppColors.suspicious,
    _ => AppColors.safe,
  };

  IconData _verdictIcon(String v) => switch (v) {
    "dangerous" => Icons.gpp_bad_rounded,
    "suspicious" => Icons.warning_amber_rounded,
    _ => Icons.verified_user_rounded,
  };

  String _formatDate(String iso) {
    try {
      return DateFormat('dd MMM yyyy, HH:mm').format(DateTime.parse(iso).toLocal());
    } catch (_) {
      return iso;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.surface,
      appBar: AppBar(
        title: const Text('Scan History'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          if (_records.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_outline, size: 22),
              tooltip: 'Clear all',
              onPressed: _clearAll,
            ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: AppColors.accent))
          : _records.isEmpty
              ? Center(
                  child: Column(mainAxisSize: MainAxisSize.min, children: [
                    Icon(Icons.history_rounded, size: 64, color: AppColors.textSecondary.withValues(alpha: 0.3)),
                    const SizedBox(height: 16),
                    const Text('No scans yet',
                        style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
                    const SizedBox(height: 6),
                    Text('Your scan history will appear here',
                        style: TextStyle(fontSize: 14, color: AppColors.textSecondary.withValues(alpha: 0.7))),
                  ]),
                )
              : ListView.builder(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
                  itemCount: _records.length,
                  itemBuilder: (context, i) {
                    final rec = _records[i];
                    final verdict = rec['verdict'] ?? 'safe';
                    final score = ((rec['score'] as num?) ?? 0.0) * 100;
                    final url = rec['finalUrl'] ?? rec['raw'] ?? '';
                    final date = rec['scannedAt'] ?? '';
                    final color = _verdictColor(verdict);

                    return Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: Container(
                        decoration: BoxDecoration(
                          color: AppColors.cardBg,
                          borderRadius: BorderRadius.circular(14),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withValues(alpha: 0.04),
                              blurRadius: 10,
                              offset: const Offset(0, 2),
                            ),
                          ],
                        ),
                        child: Padding(
                          padding: const EdgeInsets.all(14),
                          child: Row(children: [
                            // Verdict icon
                            Container(
                              width: 42, height: 42,
                              decoration: BoxDecoration(
                                color: color.withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(12),
                              ),
                              child: Icon(_verdictIcon(verdict), color: color, size: 22),
                            ),
                            const SizedBox(width: 12),
                            // URL + timestamp
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    url.length > 45 ? '${url.substring(0, 42)}...' : url,
                                    style: const TextStyle(
                                      fontSize: 13, fontFamily: 'monospace',
                                      fontWeight: FontWeight.w500,
                                    ),
                                    maxLines: 1, overflow: TextOverflow.ellipsis,
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    date.isNotEmpty ? _formatDate(date) : 'Unknown date',
                                    style: TextStyle(fontSize: 11, color: AppColors.textSecondary),
                                  ),
                                ],
                              ),
                            ),
                            const SizedBox(width: 8),
                            // Verdict badge
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                              decoration: BoxDecoration(
                                color: color.withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(20),
                              ),
                              child: Text(
                                '${score.toStringAsFixed(0)}%',
                                style: TextStyle(
                                  color: color, fontSize: 12, fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          ]),
                        ),
                      ),
                    );
                  },
                ),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════
// Result Page
// ══════════════════════════════════════════════════════════════════════
class ResultPage extends StatelessWidget {
  final AnalysisResult result;
  final VoidCallback? onLogout;
  const ResultPage({super.key, required this.result, this.onLogout});

  Color _verdictColor(String v) => switch(v) {
    "dangerous" => AppColors.dangerous,
    "suspicious" => AppColors.suspicious,
    _ => AppColors.safe,
  };

  Color _verdictBgColor(String v) => switch(v) {
    "dangerous" => AppColors.dangerousLight,
    "suspicious" => AppColors.suspiciousLight,
    _ => AppColors.safeLight,
  };

  IconData _verdictIcon(String v) => switch(v) {
    "dangerous" => Icons.gpp_bad_rounded,
    "suspicious" => Icons.warning_amber_rounded,
    _ => Icons.verified_user_rounded,
  };

  String _verdictHeadline(String v) => switch(v) {
    "dangerous" => "Dangerous link detected",
    "suspicious" => "This link looks suspicious",
    _ => "This link looks safe",
  };

  @override
  Widget build(BuildContext context) {
    final v = result.verdict.verdict;
    final color = _verdictColor(v);
    final bgColor = _verdictBgColor(v);
    final scorePercent = (result.verdict.score * 100).toStringAsFixed(0);

    return Scaffold(
      backgroundColor: AppColors.surface,
      appBar: AppBar(
        title: const Text('Scan Result'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, size: 20),
          onPressed: () => Navigator.of(context).pop(),
        ),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Verdict Card ──
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [color, color.withValues(alpha: 0.8)],
                begin: Alignment.topLeft, end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(18),
              boxShadow: [BoxShadow(color: color.withValues(alpha: 0.3), blurRadius: 16, offset: const Offset(0, 6))],
            ),
            child: Row(children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Icon(_verdictIcon(v), color: Colors.white, size: 28),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(_verdictHeadline(v),
                    style: const TextStyle(color: Colors.white, fontSize: 17, fontWeight: FontWeight.w700)),
                  const SizedBox(height: 4),
                  Text('Score: $scorePercent%',
                    style: TextStyle(color: Colors.white.withValues(alpha: 0.8), fontSize: 13)),
                ]),
              ),
            ]),
          ),

          const SizedBox(height: 16),

          // ── URL Card ──
          _card(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Icon(Icons.link, size: 18, color: AppColors.textSecondary),
                const SizedBox(width: 6),
                Text(result.finalUrl != null ? 'Final URL' : 'Content',
                  style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13, color: AppColors.textSecondary)),
              ]),
              const SizedBox(height: 10),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppColors.surface,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: SelectableText(
                  result.finalUrl ?? result.raw,
                  style: const TextStyle(fontSize: 13, fontFamily: 'monospace', height: 1.4),
                ),
              ),
              const SizedBox(height: 14),
              Row(children: [
                if (v != "dangerous" && result.finalUrl != null)
                  Expanded(
                    child: SizedBox(
                      height: 44,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.open_in_new, size: 16),
                        label: const Text('Open link'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.navy,
                          foregroundColor: Colors.white,
                          elevation: 0,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                        onPressed: () async {
                          final uri = Uri.tryParse(result.finalUrl!);
                          if (uri != null) await launchUrl(uri, mode: LaunchMode.externalApplication);
                        },
                      ),
                    ),
                  ),
                if (v != "dangerous" && result.finalUrl != null)
                  const SizedBox(width: 10),
                Expanded(
                  child: SizedBox(
                    height: 44,
                    child: OutlinedButton.icon(
                      icon: const Icon(Icons.qr_code_scanner, size: 16),
                      label: const Text('Scan again'),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.navy,
                        side: const BorderSide(color: AppColors.navy, width: 1.5),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      onPressed: () => Navigator.of(context).pop(),
                    ),
                  ),
                ),
              ]),
            ]),
          ),

          const SizedBox(height: 12),

          // ── Security Details ──
          _SecurityDetailsCard(result: result),

          // ── Timestamp ──
          if (result.scannedAt.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Center(
                child: Text('Scanned on ${_formatDate(result.scannedAt)}',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 11)),
              ),
            ),

          // ── Caution banner ──
          if (v != "safe") ...[
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: bgColor,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: color.withValues(alpha: 0.2)),
              ),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Icon(Icons.warning_amber_rounded, color: color, size: 22),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('Proceed with Caution',
                      style: TextStyle(fontWeight: FontWeight.w700, color: color, fontSize: 14)),
                    const SizedBox(height: 4),
                    Text(
                      'This content has been flagged as potentially $v. Do not open suspicious links or download files from untrusted sources.',
                      style: TextStyle(color: color.withValues(alpha: 0.8), fontSize: 13, height: 1.4),
                    ),
                  ]),
                ),
              ]),
            ),
          ],

          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Widget _card({required Widget child}) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppColors.cardBg,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [BoxShadow(color: Colors.black.withValues(alpha: 0.04), blurRadius: 12, offset: const Offset(0, 2))],
      ),
      child: child,
    );
  }

  String _formatDate(String iso) {
    try {
      return DateFormat('dd/MM/yyyy, HH:mm:ss').format(DateTime.parse(iso).toLocal());
    } catch (_) { return iso; }
  }
}

// ══════════════════════════════════════════════════════════════════════
// Security Details Expandable Card
// ══════════════════════════════════════════════════════════════════════
class _SecurityDetailsCard extends StatefulWidget {
  final AnalysisResult result;
  const _SecurityDetailsCard({required this.result});
  @override
  State<_SecurityDetailsCard> createState() => _SecurityDetailsCardState();
}

class _SecurityDetailsCardState extends State<_SecurityDetailsCard> {
  bool expand = false;

  @override
  Widget build(BuildContext context) {
    final r = widget.result;
    final heuristics = r.details["heuristics"] as List? ?? [];

    return Container(
      decoration: BoxDecoration(
        color: AppColors.cardBg,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [BoxShadow(color: Colors.black.withValues(alpha: 0.04), blurRadius: 12, offset: const Offset(0, 2))],
      ),
      child: Column(children: [
        // Header
        InkWell(
          onTap: () => setState(() => expand = !expand),
          borderRadius: BorderRadius.circular(16),
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Row(children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: AppColors.navy.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.security, color: AppColors.navy, size: 18),
              ),
              const SizedBox(width: 10),
              const Expanded(
                child: Text('Security details',
                  style: TextStyle(fontWeight: FontWeight.w700, fontSize: 15, color: AppColors.textPrimary)),
              ),
              AnimatedRotation(
                turns: expand ? 0.5 : 0,
                duration: const Duration(milliseconds: 200),
                child: const Icon(Icons.keyboard_arrow_down, color: AppColors.textSecondary),
              ),
            ]),
          ),
        ),

        // Expandable content
        AnimatedCrossFade(
          firstChild: const SizedBox.shrink(),
          secondChild: Padding(
            padding: const EdgeInsets.fromLTRB(18, 0, 18, 18),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Container(height: 1, color: Colors.grey.shade100),
              const SizedBox(height: 14),

              // Heuristic flags
              if (heuristics.isNotEmpty) ...[
                ...heuristics.map((flag) => Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Container(
                      width: 6, height: 6, margin: const EdgeInsets.only(top: 7, right: 10),
                      decoration: const BoxDecoration(color: AppColors.dangerous, shape: BoxShape.circle),
                    ),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(flag.toString(), style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
                        Text(_flagDescription(flag.toString()),
                          style: TextStyle(fontSize: 12, color: AppColors.textSecondary, height: 1.3)),
                      ]),
                    ),
                  ]),
                )),
                const SizedBox(height: 6),
              ],

              // API results
              _infoRow('Google Safe Browsing', r.details["gsb"]?.toString() ?? "n/a"),
              _infoRow('PhishTank', r.details["phishtank"]?.toString() ?? "n/a"),
              if (r.details["ml_score"] != null)
                _infoRow('ML Risk Score', '${((r.details["ml_score"] as num) * 100).toStringAsFixed(1)}%'),

              // Redirect chain
              if (r.chain.isNotEmpty) ...[
                const SizedBox(height: 14),
                const Text('Redirect chain', style: TextStyle(fontWeight: FontWeight.w700, fontSize: 13)),
                const SizedBox(height: 8),
                ...r.chain.asMap().entries.map((e) => Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Container(
                      width: 22, height: 22, alignment: Alignment.center,
                      decoration: BoxDecoration(color: AppColors.navy.withValues(alpha: 0.08), borderRadius: BorderRadius.circular(6)),
                      child: Text('${e.key + 1}', style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w700, color: AppColors.navy)),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(e.value.url, style: const TextStyle(fontSize: 11, fontFamily: 'monospace')),
                        if (e.value.status > 0)
                          Text('HTTP ${e.value.status}', style: TextStyle(fontSize: 10, color: AppColors.textSecondary)),
                      ]),
                    ),
                  ]),
                )),
              ],
            ]),
          ),
          crossFadeState: expand ? CrossFadeState.showSecond : CrossFadeState.showFirst,
          duration: const Duration(milliseconds: 250),
        ),
      ]),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(children: [
        SizedBox(width: 140, child: Text(label, style: TextStyle(color: AppColors.textSecondary, fontSize: 12))),
        Expanded(child: Text(value, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500))),
      ]),
    );
  }

  String _flagDescription(String flag) {
    if (flag.contains('Insecure')) return 'This URL uses HTTP instead of HTTPS, which means data is not encrypted.';
    if (flag.contains('IP Address')) return 'Direct IP addresses are often used in phishing attacks to hide the real destination.';
    if (flag.contains('APK') || flag.contains('Download')) return 'This link attempts to download a file, which could contain malware.';
    if (flag.contains('Punycode')) return 'This domain uses encoded characters that may mimic a legitimate website.';
    if (flag.contains('Subdomain')) return 'Excessive subdomains can indicate a spoofed or deceptive URL.';
    if (flag.contains('TLD')) return 'This top-level domain is commonly associated with malicious websites.';
    if (flag.contains('Long')) return 'Very long URLs are often used to hide malicious content.';
    if (flag.contains('@')) return 'The @ symbol can trick browsers into ignoring the real destination.';
    if (flag.contains('Shortener')) return 'URL shorteners can mask the true destination of a link.';
    return 'This pattern was flagged as potentially risky.';
  }
}

// ══════════════════════════════════════════════════════════════════════
// Shared Widgets
// ══════════════════════════════════════════════════════════════════════
Widget _buildLogo(double size) {
  return Container(
    padding: EdgeInsets.all(size * 0.22),
    decoration: BoxDecoration(
      color: Colors.white.withValues(alpha: 0.1),
      borderRadius: BorderRadius.circular(size * 0.28),
      border: Border.all(color: AppColors.accent.withValues(alpha: 0.3), width: 1.5),
    ),
    child: Icon(Icons.qr_code_scanner_rounded, size: size * 0.55, color: AppColors.accent),
  );
}
