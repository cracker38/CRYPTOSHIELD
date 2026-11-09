import 'dart:convert';

import 'package:flutter/material.dart';
import 'firebase_service.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    await initializeFirebase();
    runApp(const FirebaseStartupGate());
  } on FirebaseStartupException catch (error) {
    runApp(FirebaseUnavailableApp(message: error.message));
  }
}

const navy = Color(0xFF07111F);
const panel = Color(0xFF101F32);
const blue = Color(0xFF43A5FF);
const mint = Color(0xFF3DDBB1);

class CryptoShieldApp extends StatefulWidget {
  const CryptoShieldApp({this.service, super.key});

  final CryptoShieldService? service;

  @override
  State<CryptoShieldApp> createState() => _CryptoShieldAppState();
}

class _CryptoShieldAppState extends State<CryptoShieldApp> {
  late final CryptoShieldService service = widget.service ?? FirebaseService();
  Map<String, dynamic>? user;
  String? startupError;

  @override
  void initState() {
    super.initState();
    _restoreUser();
  }

  Future<void> _restoreUser() async {
    try {
      final restoredUser = await service.restoreUser();
      if (mounted) {
        setState(() {
          startupError = null;
          user = restoredUser;
        });
      }
    } on ApiException catch (error) {
      if (mounted) setState(() => startupError = error.message);
    }
  }

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'CRYPTOSHIELD',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          brightness: Brightness.dark,
          scaffoldBackgroundColor: navy,
          colorScheme: ColorScheme.fromSeed(
            seedColor: blue,
            brightness: Brightness.dark,
          ),
          useMaterial3: true,
          cardTheme: CardThemeData(
            color: panel,
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(18),
            ),
          ),
          inputDecorationTheme: InputDecorationTheme(
            filled: true,
            fillColor: const Color(0xFF0C1929),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(14),
              borderSide: BorderSide.none,
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(14),
              borderSide: const BorderSide(color: blue),
            ),
          ),
        ),
        home: startupError != null
            ? FirebaseErrorPage(message: startupError!, onRetry: _restoreUser)
            : user == null
                ? AuthPage(
                    service: service,
                    onAuthenticated: (value) => setState(() => user = value),
                  )
                : MainShell(
                    service: service,
                    user: user!,
                    onSignOut: () => setState(() => user = null),
                  ),
      );
}

class FirebaseStartupGate extends StatefulWidget {
  const FirebaseStartupGate({super.key});

  @override
  State<FirebaseStartupGate> createState() => _FirebaseStartupGateState();
}

class _FirebaseStartupGateState extends State<FirebaseStartupGate> {
  late Future<void> healthCheck;

  @override
  void initState() {
    super.initState();
    healthCheck = FirebaseService().checkHealth();
  }

  void retry() => setState(() => healthCheck = FirebaseService().checkHealth());

  @override
  Widget build(BuildContext context) => FutureBuilder<void>(
        future: healthCheck,
        builder: (context, snapshot) {
          if (snapshot.hasError) {
            return FirebaseUnavailableApp(
              message: snapshot.error is ApiException
                  ? (snapshot.error! as ApiException).message
                  : snapshot.error.toString(),
              onRetry: retry,
            );
          }
          if (snapshot.connectionState != ConnectionState.done) {
            return const MaterialApp(
              home: Scaffold(
                body: Center(child: CircularProgressIndicator()),
              ),
            );
          }
          return const CryptoShieldApp();
        },
      );
}

class FirebaseUnavailableApp extends StatelessWidget {
  const FirebaseUnavailableApp({
    required this.message,
    this.onRetry,
    super.key,
  });

  final String message;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'CRYPTOSHIELD',
        home: Scaffold(
          body: Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 480),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.cloud_off_outlined,
                        size: 48, color: Colors.orange),
                    const SizedBox(height: 16),
                    const Text(
                      'Firebase is unavailable',
                      style:
                          TextStyle(fontSize: 24, fontWeight: FontWeight.w800),
                    ),
                    const SizedBox(height: 12),
                    Text(message, textAlign: TextAlign.center),
                    if (onRetry != null) ...[
                      const SizedBox(height: 20),
                      FilledButton(
                        onPressed: onRetry,
                        child: const Text('Retry connection'),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      );
}

class FirebaseErrorPage extends StatelessWidget {
  const FirebaseErrorPage({
    required this.message,
    required this.onRetry,
    super.key,
  });

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.cloud_off_outlined,
                    size: 44, color: Colors.orange),
                const SizedBox(height: 12),
                const Text('Could not verify your Firebase account.'),
                const SizedBox(height: 8),
                Text(message, textAlign: TextAlign.center),
                const SizedBox(height: 16),
                FilledButton(onPressed: onRetry, child: const Text('Retry')),
              ],
            ),
          ),
        ),
      );
}

class AuthPage extends StatefulWidget {
  const AuthPage({
    required this.service,
    required this.onAuthenticated,
    super.key,
  });

  final CryptoShieldService service;
  final ValueChanged<Map<String, dynamic>> onAuthenticated;

  @override
  State<AuthPage> createState() => _AuthPageState();
}

class _AuthPageState extends State<AuthPage> {
  final formKey = GlobalKey<FormState>();
  final email = TextEditingController();
  final password = TextEditingController();
  final confirmation = TextEditingController();
  bool creatingAccount = false;
  bool busy = false;
  bool obscurePassword = true;
  Map<String, dynamic>? challenge;
  String? challengeToken;
  String? selectedOption;

  @override
  void dispose() {
    email.dispose();
    password.dispose();
    confirmation.dispose();
    super.dispose();
  }

  Future<void> submit() async {
    if (challenge == null && !formKey.currentState!.validate()) return;
    setState(() => busy = true);
    try {
      if (challenge != null) {
        final result = await widget.service.answerChallenge(
          challengeToken!,
          selectedOption!,
        );
        if (mounted) {
          widget.onAuthenticated(result['user'] as Map<String, dynamic>);
        }
      } else if (creatingAccount) {
        await widget.service.register(email.text.trim(), password.text);
        if (mounted) {
          setState(() => creatingAccount = false);
          password.clear();
          confirmation.clear();
          showMessage(
            context,
            'Check your email to verify your address. Your registration then awaits administrator review.',
          );
        }
      } else {
        final result =
            await widget.service.login(email.text.trim(), password.text);
        if (result['status'] == 'challenge_required') {
          if (mounted) {
            setState(() {
              challenge = result['challenge'] as Map<String, dynamic>;
              challengeToken = result['challenge_token'] as String;
              selectedOption = null;
            });
          }
          return;
        }
        if (mounted) {
          widget.onAuthenticated(result['user'] as Map<String, dynamic>);
        }
      }
    } on ApiException catch (error) {
      if (mounted) showMessage(context, error.message);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Widget buildChallenge() {
    final activeChallenge = challenge!;
    final options = activeChallenge['options'] as List<dynamic>;
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const _BrandMark(),
                const SizedBox(height: 32),
                const Text(
                  'Security onboarding',
                  style: TextStyle(fontSize: 28, fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Your verified account was approved. Complete this randomly selected defensive security scenario to activate it. This knowledge check is not identity verification or multi-factor authentication.',
                  style: TextStyle(color: Colors.white60, height: 1.5),
                ),
                const SizedBox(height: 20),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(18),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Text(
                          activeChallenge['question'] as String,
                          style: const TextStyle(
                            fontSize: 17,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 12),
                        RadioGroup<String>(
                          groupValue: selectedOption,
                          onChanged: (value) {
                            if (!busy) setState(() => selectedOption = value);
                          },
                          child: Column(
                            children: options.map((item) {
                              final option = item as Map<String, dynamic>;
                              return RadioListTile<String>(
                                value: option['id'] as String,
                                title: Text(option['text'] as String),
                                enabled: !busy,
                                contentPadding: EdgeInsets.zero,
                              );
                            }).toList(),
                          ),
                        ),
                        const SizedBox(height: 12),
                        FilledButton(
                          onPressed:
                              busy || selectedOption == null ? null : submit,
                          child: busy
                              ? const SizedBox(
                                  width: 20,
                                  height: 20,
                                  child:
                                      CircularProgressIndicator(strokeWidth: 2),
                                )
                              : const Text('Submit answer'),
                        ),
                        TextButton(
                          onPressed: busy
                              ? null
                              : () => setState(() {
                                    challenge = null;
                                    challengeToken = null;
                                    selectedOption = null;
                                  }),
                          child: const Text('Back to sign in'),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (challenge != null) return buildChallenge();
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 460),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const _BrandMark(),
                const SizedBox(height: 32),
                Text(
                  creatingAccount ? 'Create your account' : 'Welcome back',
                  style: const TextStyle(
                    fontSize: 30,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  creatingAccount
                      ? 'Start with your email and a strong password.'
                      : 'Sign in to your security workspace.',
                  style: const TextStyle(color: Colors.white60),
                ),
                const SizedBox(height: 24),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Form(
                      key: formKey,
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          TextFormField(
                            controller: email,
                            keyboardType: TextInputType.emailAddress,
                            autofillHints: const [AutofillHints.email],
                            decoration: const InputDecoration(
                              labelText: 'Email address',
                              prefixIcon: Icon(Icons.alternate_email),
                            ),
                            validator: (value) {
                              final trimmed = value?.trim() ?? '';
                              return RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
                                      .hasMatch(trimmed)
                                  ? null
                                  : 'Enter a valid email address.';
                            },
                          ),
                          const SizedBox(height: 14),
                          TextFormField(
                            controller: password,
                            obscureText: obscurePassword,
                            autofillHints: creatingAccount
                                ? const [AutofillHints.newPassword]
                                : const [AutofillHints.password],
                            decoration: InputDecoration(
                              labelText: 'Password',
                              prefixIcon: const Icon(Icons.lock_outline),
                              suffixIcon: IconButton(
                                onPressed: () => setState(
                                  () => obscurePassword = !obscurePassword,
                                ),
                                icon: Icon(
                                  obscurePassword
                                      ? Icons.visibility_outlined
                                      : Icons.visibility_off_outlined,
                                ),
                              ),
                            ),
                            validator: (value) {
                              final length = value?.length ?? 0;
                              if (creatingAccount && length < 12) {
                                return 'Use at least 12 characters.';
                              }
                              if (length == 0) return 'Enter your password.';
                              return null;
                            },
                          ),
                          if (creatingAccount) ...[
                            const SizedBox(height: 14),
                            TextFormField(
                              controller: confirmation,
                              obscureText: obscurePassword,
                              decoration: const InputDecoration(
                                labelText: 'Confirm password',
                                prefixIcon: Icon(Icons.verified_user_outlined),
                              ),
                              validator: (value) => value == password.text
                                  ? null
                                  : 'Passwords do not match.',
                            ),
                            const SizedBox(height: 12),
                            const Text(
                              'Use 12 or more characters. Your password is stored as a one-way hash.',
                              style: TextStyle(
                                color: Colors.white54,
                                fontSize: 12,
                                height: 1.4,
                              ),
                            ),
                          ],
                          const SizedBox(height: 22),
                          FilledButton(
                            onPressed: busy ? null : submit,
                            child: Padding(
                              padding: const EdgeInsets.symmetric(vertical: 12),
                              child: busy
                                  ? const SizedBox(
                                      height: 20,
                                      width: 20,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                      ),
                                    )
                                  : Text(
                                      creatingAccount
                                          ? 'Create account'
                                          : 'Sign in',
                                    ),
                            ),
                          ),
                          TextButton(
                            onPressed: busy
                                ? null
                                : () => setState(
                                      () => creatingAccount = !creatingAccount,
                                    ),
                            child: Text(
                              creatingAccount
                                  ? 'Already have an account? Sign in'
                                  : 'New here? Create an account',
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                const Text(
                  'Connects securely to Firebase Authentication and Firestore.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.white38, fontSize: 12),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class MainShell extends StatefulWidget {
  const MainShell({
    required this.service,
    required this.user,
    required this.onSignOut,
    super.key,
  });

  final CryptoShieldService service;
  final Map<String, dynamic> user;
  final VoidCallback onSignOut;

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  int index = 0;

  @override
  Widget build(BuildContext context) {
    final isAdmin = widget.user['role'] == 'admin';
    final pages = <Widget>[
      HomePage(user: widget.user),
      MessagesPage(service: widget.service),
      AnalyzerPage(service: widget.service),
      LabPage(service: widget.service),
      if (isAdmin) AdminPage(service: widget.service, currentUser: widget.user),
      ProfilePage(
        user: widget.user,
        onSignOut: () async {
          try {
            await widget.service.logout();
            widget.onSignOut();
          } on ApiException catch (error) {
            if (context.mounted) showMessage(context, error.message);
          }
        },
      ),
    ];
    final labels = <String>[
      'Overview',
      'Messages',
      'Analyzer',
      'Lab',
      if (isAdmin) 'Admin',
      'Account',
    ];
    final icons = <IconData>[
      Icons.grid_view_rounded,
      Icons.forum_outlined,
      Icons.manage_search,
      Icons.science_outlined,
      if (isAdmin) Icons.admin_panel_settings_outlined,
      Icons.person_outline,
    ];

    return Scaffold(
      body: SafeArea(child: IndexedStack(index: index, children: pages)),
      bottomNavigationBar: NavigationBar(
        backgroundColor: const Color(0xFF0B1726),
        selectedIndex: index,
        onDestinationSelected: (value) => setState(() => index = value),
        destinations: List.generate(
          labels.length,
          (i) => NavigationDestination(icon: Icon(icons[i]), label: labels[i]),
        ),
      ),
    );
  }
}

class _BrandMark extends StatelessWidget {
  const _BrandMark();

  @override
  Widget build(BuildContext context) => Row(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: blue.withValues(alpha: .14),
              borderRadius: BorderRadius.circular(15),
            ),
            child:
                const Icon(Icons.shield_moon_outlined, color: blue, size: 28),
          ),
          const SizedBox(width: 13),
          const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'CRYPTOSHIELD',
                style: TextStyle(
                  color: blue,
                  fontSize: 14,
                  letterSpacing: 1.8,
                  fontWeight: FontWeight.w800,
                ),
              ),
              Text(
                'SECURITY WORKSPACE',
                style: TextStyle(
                  color: Colors.white54,
                  fontSize: 10,
                  letterSpacing: 1.1,
                ),
              ),
            ],
          ),
        ],
      );
}

class PageFrame extends StatelessWidget {
  const PageFrame({
    required this.title,
    required this.subtitle,
    required this.child,
    super.key,
  });

  final String title;
  final String subtitle;
  final Widget child;

  @override
  Widget build(BuildContext context) => CustomScrollView(
        slivers: [
          SliverPadding(
            padding: const EdgeInsets.fromLTRB(20, 18, 20, 24),
            sliver: SliverList(
              delegate: SliverChildListDelegate([
                const _BrandMark(),
                const SizedBox(height: 28),
                Text(
                  title,
                  style: const TextStyle(
                    fontSize: 27,
                    fontWeight: FontWeight.w800,
                    letterSpacing: -.6,
                  ),
                ),
                const SizedBox(height: 5),
                Text(subtitle, style: const TextStyle(color: Colors.white60)),
                const SizedBox(height: 22),
                child,
              ]),
            ),
          ),
        ],
      );
}

Widget sectionTitle(String text, {String? trailing}) => Padding(
      padding: const EdgeInsets.only(bottom: 12, top: 8),
      child: Row(
        children: [
          Expanded(
            child: Text(
              text,
              style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
            ),
          ),
          if (trailing != null)
            Text(
              trailing,
              style: const TextStyle(color: blue, fontSize: 12),
            ),
        ],
      ),
    );

Widget metric(String label, String value, IconData icon, Color color) =>
    Expanded(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: color, size: 20),
              const SizedBox(height: 13),
              Text(
                value,
                style: const TextStyle(
                  fontSize: 21,
                  fontWeight: FontWeight.w800,
                ),
              ),
              Text(
                label,
                style: const TextStyle(fontSize: 11, color: Colors.white60),
              ),
            ],
          ),
        ),
      ),
    );

Widget featureTile(
  IconData icon,
  String title,
  String desc,
  Color color,
) =>
    Card(
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 15, vertical: 7),
        leading: Container(
          width: 42,
          height: 42,
          decoration: BoxDecoration(
            color: color.withValues(alpha: .13),
            borderRadius: BorderRadius.circular(13),
          ),
          child: Icon(icon, color: color),
        ),
        title: Text(
          title,
          style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
        ),
        subtitle: Text(
          desc,
          style: const TextStyle(color: Colors.white60, fontSize: 12),
        ),
      ),
    );

class HomePage extends StatelessWidget {
  const HomePage({required this.user, super.key});
  final Map<String, dynamic> user;

  @override
  Widget build(BuildContext context) => PageFrame(
        title: 'Your workspace',
        subtitle: 'A clear view of your CRYPTOSHIELD tools and account.',
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Card(
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(19),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(18),
                  gradient: const LinearGradient(
                    colors: [Color(0xFF12385A), Color(0xFF17233E)],
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Row(
                      children: [
                        Icon(Icons.verified_user_outlined, color: mint),
                        SizedBox(width: 8),
                        Text(
                          'ACCOUNT ACTIVE',
                          style: TextStyle(
                            color: mint,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 1,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 14),
                    Text(
                      'Welcome, ${user['username']}',
                      style: const TextStyle(
                        fontSize: 19,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const SizedBox(height: 7),
                    Text(
                      user['role'] == 'admin'
                          ? 'Administrator access is enabled for this account.'
                          : 'Your account is ready. Choose a tool to get started.',
                      style:
                          const TextStyle(color: Colors.white70, height: 1.4),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 18),
            sectionTitle('Workspace tools'),
            featureTile(
              Icons.forum_outlined,
              'Messages',
              'Send and receive messages between registered accounts.',
              blue,
            ),
            featureTile(
              Icons.manage_search,
              'Cipher intelligence',
              'Inspect authorized samples for recognizable formats.',
              mint,
            ),
            featureTile(
              Icons.school_outlined,
              'Cryptography lab',
              'Practice with classical ciphers in a local training exercise.',
              Colors.orange,
            ),
            const SizedBox(height: 12),
            const Card(
              child: Padding(
                padding: EdgeInsets.all(15),
                child: Text(
                  'Messages use Firestore encryption at rest, but are not end-to-end encrypted. Do not use this service for sensitive or confidential conversations.',
                  style: TextStyle(
                      color: Colors.white60, fontSize: 12, height: 1.5),
                ),
              ),
            ),
          ],
        ),
      );
}

class MessagesPage extends StatefulWidget {
  const MessagesPage({required this.service, super.key});
  final CryptoShieldService service;

  @override
  State<MessagesPage> createState() => _MessagesPageState();
}

class _MessagesPageState extends State<MessagesPage> {
  final recipient = TextEditingController();
  final composer = TextEditingController();
  List<Map<String, dynamic>> messages = [];
  String? activeRecipient;
  bool busy = false;

  @override
  void dispose() {
    recipient.dispose();
    composer.dispose();
    super.dispose();
  }

  Future<void> loadMessages() async {
    final email = recipient.text.trim();
    if (email.isEmpty) {
      showMessage(context, 'Enter the other account email first.');
      return;
    }
    setState(() => busy = true);
    try {
      final result = await widget.service.getMessages(email);
      if (!mounted) return;
      setState(() {
        activeRecipient = email;
        messages = result;
      });
    } on ApiException catch (error) {
      if (mounted) showMessage(context, error.message);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> sendMessage() async {
    final text = composer.text.trim();
    final email = recipient.text.trim();
    if (email.isEmpty || text.isEmpty) {
      showMessage(context, 'Enter a recipient and message.');
      return;
    }
    setState(() => busy = true);
    try {
      await widget.service.sendMessage(email, text);
      composer.clear();
      await loadMessages();
    } on ApiException catch (error) {
      if (mounted) showMessage(context, error.message);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => PageFrame(
        title: 'Messages',
        subtitle: 'Start a conversation with another registered account.',
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Card(
              child: Padding(
                padding: EdgeInsets.all(14),
                child: Row(
                  children: [
                    Icon(Icons.info_outline, color: Colors.orange),
                    SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Messages are encrypted at rest by Firestore, not end-to-end encrypted.',
                        style: TextStyle(fontSize: 12, color: Colors.white70),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            sectionTitle('Conversation'),
            TextField(
              controller: recipient,
              keyboardType: TextInputType.emailAddress,
              decoration: InputDecoration(
                labelText: 'Recipient email',
                suffixIcon: IconButton(
                  onPressed: busy ? null : loadMessages,
                  icon: const Icon(Icons.arrow_forward),
                ),
              ),
              onSubmitted: (_) => loadMessages(),
            ),
            const SizedBox(height: 14),
            if (activeRecipient != null)
              Text(
                'Conversation with $activeRecipient',
                style: const TextStyle(color: Colors.white60),
              ),
            const SizedBox(height: 8),
            if (messages.isEmpty && activeRecipient != null)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 20),
                child: Text(
                  'No messages yet. Send the first message below.',
                  style: TextStyle(color: Colors.white54),
                ),
              ),
            ...messages.map((message) {
              final sentByMe = message['sender_username'] != activeRecipient;
              return Align(
                alignment:
                    sentByMe ? Alignment.centerRight : Alignment.centerLeft,
                child: Container(
                  margin: const EdgeInsets.only(bottom: 9),
                  padding: const EdgeInsets.all(13),
                  constraints: const BoxConstraints(maxWidth: 310),
                  decoration: BoxDecoration(
                    color: sentByMe
                        ? const Color(0xFF16436A)
                        : const Color(0xFF17243A),
                    borderRadius: BorderRadius.circular(15),
                  ),
                  child: Text(message['content'] as String),
                ),
              );
            }),
            const SizedBox(height: 8),
            TextField(
              controller: composer,
              minLines: 1,
              maxLines: 4,
              decoration: InputDecoration(
                hintText: 'Write a message',
                suffixIcon: IconButton(
                  onPressed: busy ? null : sendMessage,
                  icon: const Icon(Icons.send, color: blue),
                ),
              ),
              onSubmitted: (_) => sendMessage(),
            ),
          ],
        ),
      );
}

class AdminPage extends StatefulWidget {
  const AdminPage({
    required this.service,
    required this.currentUser,
    super.key,
  });

  final CryptoShieldService service;
  final Map<String, dynamic> currentUser;

  @override
  State<AdminPage> createState() => _AdminPageState();
}

class _AdminPageState extends State<AdminPage> {
  Map<String, dynamic>? overview;
  String? error;
  bool loading = true;

  @override
  void initState() {
    super.initState();
    refresh();
  }

  Future<void> refresh() async {
    setState(() {
      loading = true;
      error = null;
    });
    try {
      final result = await widget.service.adminOverview();
      if (mounted) setState(() => overview = result);
    } on ApiException catch (exception) {
      if (mounted) setState(() => error = exception.message);
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> changeStatus(Map<String, dynamic> user) async {
    final id = user['id'] as String;
    final isActive = user['is_active'] as bool;
    try {
      await widget.service.setUserActive(id, !isActive);
      await refresh();
    } on ApiException catch (exception) {
      if (mounted) showMessage(context, exception.message);
    }
  }

  Future<void> reviewUser(
    Map<String, dynamic> user,
    String decision,
  ) async {
    final id = user['id'] as String;
    try {
      await widget.service.reviewUser(id, decision);
      await refresh();
    } on ApiException catch (exception) {
      if (mounted) showMessage(context, exception.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final counts = overview?['counts'] as Map<String, dynamic>?;
    final users = overview?['users'] as List<dynamic>? ?? const [];
    return PageFrame(
      title: 'Administration',
      subtitle: 'Manage user access and review system activity.',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (loading) const LinearProgressIndicator(),
          if (error != null)
            Card(
              child: ListTile(
                leading: const Icon(Icons.error_outline, color: Colors.orange),
                title: Text(error!),
                trailing: IconButton(
                  onPressed: refresh,
                  icon: const Icon(Icons.refresh),
                ),
              ),
            ),
          if (counts != null) ...[
            Row(
              children: [
                metric(
                  'Accounts',
                  '${counts['users']}',
                  Icons.people_outline,
                  blue,
                ),
                const SizedBox(width: 10),
                metric(
                  'Active',
                  '${counts['active_users']}',
                  Icons.verified_user_outlined,
                  mint,
                ),
              ],
            ),
            Row(
              children: [
                metric(
                  'Conversations',
                  '${counts['conversations']}',
                  Icons.forum_outlined,
                  Colors.orange,
                ),
                const SizedBox(width: 10),
                metric(
                  'Messages',
                  '${counts['messages']}',
                  Icons.chat_bubble_outline,
                  Colors.purpleAccent,
                ),
              ],
            ),
          ],
          sectionTitle('Accounts', trailing: '${users.length} TOTAL'),
          if (users.isEmpty && !loading && error == null)
            const Text('No accounts found.'),
          ...users.map((item) {
            final user = item as Map<String, dynamic>;
            final isSelf = user['id'] == widget.currentUser['id'];
            final active = user['is_active'] as bool;
            final accountStatus = user['account_status'] as String;
            return Card(
              child: ListTile(
                leading: CircleAvatar(
                  backgroundColor:
                      active ? const Color(0xFF16436A) : Colors.white12,
                  child: Icon(
                    user['role'] == 'admin'
                        ? Icons.admin_panel_settings_outlined
                        : Icons.person_outline,
                    color: active ? Colors.white : Colors.white54,
                  ),
                ),
                title: Text(user['username'] as String),
                subtitle: Text(
                  '${user['role']} · ${accountStatus.replaceAll('_', ' ')}',
                ),
                trailing: isSelf
                    ? const Text('You', style: TextStyle(color: mint))
                    : accountStatus == 'pending_review'
                        ? Wrap(
                            spacing: 2,
                            children: [
                              IconButton(
                                tooltip: 'Approve applicant',
                                onPressed: loading
                                    ? null
                                    : () => reviewUser(user, 'approve'),
                                icon: const Icon(
                                  Icons.check_circle_outline,
                                  color: mint,
                                ),
                              ),
                              IconButton(
                                tooltip: 'Reject applicant',
                                onPressed: loading
                                    ? null
                                    : () => reviewUser(user, 'reject'),
                                icon: const Icon(
                                  Icons.cancel_outlined,
                                  color: Colors.orange,
                                ),
                              ),
                            ],
                          )
                        : accountStatus == 'challenge_required'
                            ? IconButton(
                                tooltip: 'Revoke approval',
                                onPressed: loading
                                    ? null
                                    : () => reviewUser(user, 'reject'),
                                icon: const Icon(
                                  Icons.block_outlined,
                                  color: Colors.orange,
                                ),
                              )
                            : accountStatus == 'active' ||
                                    accountStatus == 'disabled'
                                ? Switch(
                                    value: active,
                                    onChanged: loading
                                        ? null
                                        : (_) => changeStatus(user),
                                  )
                                : null,
              ),
            );
          }),
          const SizedBox(height: 10),
          OutlinedButton.icon(
            onPressed: loading ? null : refresh,
            icon: const Icon(Icons.refresh),
            label: const Text('Refresh data'),
          ),
        ],
      ),
    );
  }
}

class AnalyzerPage extends StatefulWidget {
  const AnalyzerPage({required this.service, super.key});
  final CryptoShieldService service;

  @override
  State<AnalyzerPage> createState() => _AnalyzerPageState();
}

class _AnalyzerPageState extends State<AnalyzerPage> {
  final input = TextEditingController();
  String? report;
  List<Map<String, dynamic>> history = [];
  String? historyError;
  bool loadingHistory = true;
  bool saving = false;

  @override
  void initState() {
    super.initState();
    loadHistory();
  }

  @override
  void dispose() {
    input.dispose();
    super.dispose();
  }

  Future<void> loadHistory() async {
    setState(() {
      loadingHistory = true;
      historyError = null;
    });
    try {
      final records = await widget.service.getToolHistory('analysis');
      if (mounted) setState(() => history = records);
    } on ApiException catch (error) {
      if (mounted) setState(() => historyError = error.message);
    } finally {
      if (mounted) setState(() => loadingHistory = false);
    }
  }

  Future<void> saveAnalysis() async {
    final sample = input.text;
    if (sample.trim().isEmpty) {
      showMessage(context, 'Enter a sample to analyze.');
      return;
    }
    if (sample.length > 20000) {
      showMessage(context, 'Samples must be 20,000 characters or fewer.');
      return;
    }
    final analysisResult = analyze(sample);
    setState(() => saving = true);
    try {
      await widget.service.saveToolRecord('analysis', sample, analysisResult);
      if (mounted) setState(() => report = analysisResult);
      await loadHistory();
    } on ApiException catch (error) {
      if (mounted) showMessage(context, error.message);
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  String analyze(String raw) {
    final sample = raw.trim();
    if (sample.isEmpty) return 'Enter a sample to analyze.';
    final hex = RegExp(r'^(?:[0-9a-fA-F]{2})+$').hasMatch(sample);
    var base64Like = false;
    try {
      final decoded = base64.decode(base64.normalize(sample));
      base64Like = decoded.isNotEmpty &&
          base64.encode(decoded).replaceAll('=', '') ==
              sample.replaceAll('=', '');
    } on FormatException {
      base64Like = false;
    }
    final prefix =
        sample.startsWith('Salted__') || sample.startsWith('U2FsdGVkX1');
    return [
      'PRELIMINARY FORMAT REPORT',
      'Input length: ${sample.length} characters',
      'Hexadecimal-like: ${hex ? "Yes" : "No"}',
      'Base64-like: ${base64Like ? "Yes" : "No"}',
      'OpenSSL salted marker: ${prefix ? "Possible" : "Not detected"}',
      '',
      'Base64 is an encoding, not encryption. A matching hexadecimal pattern is also not proof of encryption.',
      'Ciphertext alone usually cannot reveal its algorithm, key, mode or security strength. No decryption or password guessing was attempted.',
    ].join('\n');
  }

  @override
  Widget build(BuildContext context) => PageFrame(
        title: 'Cipher intelligence',
        subtitle:
            'Inspect authorized samples for recognizable formats and observable characteristics.',
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Card(
              child: ListTile(
                leading: Icon(Icons.shield_outlined, color: mint),
                title: Text('Authorization first'),
                subtitle: Text(
                  'Analyze only data you own or may examine. Submitted samples and reports are saved in your private Firestore history.',
                ),
              ),
            ),
            sectionTitle('Sample input'),
            TextField(
              controller: input,
              minLines: 5,
              maxLines: 8,
              decoration: const InputDecoration(
                hintText: 'Paste Base64, hexadecimal or another sample...',
              ),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: saving ? null : saveAnalysis,
                icon: const Icon(Icons.manage_search),
                label:
                    Text(saving ? 'Saving to Firestore...' : 'Analyze sample'),
              ),
            ),
            if (report != null) ...[
              sectionTitle('Analysis result'),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(15),
                  child: SelectableText(
                    report!,
                    style: const TextStyle(height: 1.55, fontSize: 12),
                  ),
                ),
              ),
            ],
            toolHistorySection(
              title: 'Saved analyses',
              records: history,
              loading: loadingHistory,
              error: historyError,
              onRefresh: loadHistory,
            ),
          ],
        ),
      );
}

class LabPage extends StatefulWidget {
  const LabPage({required this.service, super.key});
  final CryptoShieldService service;

  @override
  State<LabPage> createState() => _LabPageState();
}

class _LabPageState extends State<LabPage> {
  final input = TextEditingController();
  final shift = TextEditingController(text: '3');
  String result = '';
  List<Map<String, dynamic>> history = [];
  String? historyError;
  bool loadingHistory = true;
  bool saving = false;

  @override
  void initState() {
    super.initState();
    loadHistory();
  }

  @override
  void dispose() {
    input.dispose();
    shift.dispose();
    super.dispose();
  }

  String caesar(String text, int amount) =>
      String.fromCharCodes(text.runes.map((code) {
        final shift = amount % 26;
        if (code >= 65 && code <= 90) return 65 + (code - 65 - shift + 26) % 26;
        if (code >= 97 && code <= 122) {
          return 97 + (code - 97 - shift + 26) % 26;
        }
        return code;
      }));

  Future<void> loadHistory() async {
    setState(() {
      loadingHistory = true;
      historyError = null;
    });
    try {
      final records = await widget.service.getToolHistory('lab');
      if (mounted) setState(() => history = records);
    } on ApiException catch (error) {
      if (mounted) setState(() => historyError = error.message);
    } finally {
      if (mounted) setState(() => loadingHistory = false);
    }
  }

  Future<void> decodeExercise() async {
    final text = input.text;
    final amount = int.tryParse(shift.text);
    if (text.trim().isEmpty) {
      showMessage(context, 'Enter training ciphertext.');
      return;
    }
    if (amount == null) {
      showMessage(context, 'Enter a whole-number shift amount.');
      return;
    }
    final savedInput = 'shift=$amount\n$text';
    if (savedInput.length > 20000) {
      showMessage(context, 'Training text must be 20,000 characters or fewer.');
      return;
    }
    final decoded = caesar(text, amount);
    setState(() => saving = true);
    try {
      await widget.service.saveToolRecord(
        'lab',
        savedInput,
        decoded,
      );
      if (mounted) setState(() => result = decoded);
      await loadHistory();
    } on ApiException catch (error) {
      if (mounted) showMessage(context, error.message);
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  @override
  Widget build(BuildContext context) => PageFrame(
        title: 'Cryptography lab',
        subtitle:
            'Practice concepts with safe training exercises saved to Firestore.',
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Card(
              child: ListTile(
                leading: Icon(Icons.school_outlined, color: blue),
                title: Text('Training sandbox · Firestore history'),
                subtitle: Text(
                  'Classical ciphers are educational and cannot protect real information.',
                ),
              ),
            ),
            sectionTitle('Caesar cipher decoder'),
            TextField(
              controller: input,
              minLines: 2,
              maxLines: 4,
              decoration: const InputDecoration(
                hintText: 'Enter training ciphertext',
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: shift,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(labelText: 'Shift amount'),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton(
                onPressed: saving ? null : decodeExercise,
                child:
                    Text(saving ? 'Saving to Firestore...' : 'Decode exercise'),
              ),
            ),
            if (result.isNotEmpty)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(14),
                  child: SelectableText('Training output: $result'),
                ),
              ),
            toolHistorySection(
              title: 'Saved exercises',
              records: history,
              loading: loadingHistory,
              error: historyError,
              onRefresh: loadHistory,
            ),
          ],
        ),
      );
}

Widget toolHistorySection({
  required String title,
  required List<Map<String, dynamic>> records,
  required bool loading,
  required String? error,
  required VoidCallback onRefresh,
}) =>
    Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        sectionTitle(title, trailing: 'LATEST ${records.length}'),
        if (loading) const LinearProgressIndicator(),
        if (error != null)
          Card(
            child: ListTile(
              title: Text(error),
              trailing: IconButton(
                onPressed: onRefresh,
                icon: const Icon(Icons.refresh),
              ),
            ),
          ),
        if (!loading && error == null && records.isEmpty)
          const Text(
            'No saved entries yet.',
            style: TextStyle(color: Colors.white54),
          ),
        ...records.map(
          (record) => Card(
            child: ExpansionTile(
              title: Text(
                record['created_at'] as String? ?? 'Saved entry',
                style: const TextStyle(fontSize: 13),
              ),
              childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('INPUT',
                    style: TextStyle(color: blue, fontSize: 11)),
                const SizedBox(height: 4),
                SelectableText(record['input'] as String),
                const SizedBox(height: 12),
                const Text('RESULT',
                    style: TextStyle(color: mint, fontSize: 11)),
                const SizedBox(height: 4),
                SelectableText(record['result'] as String),
              ],
            ),
          ),
        ),
      ],
    );

class ProfilePage extends StatelessWidget {
  const ProfilePage({
    required this.user,
    required this.onSignOut,
    super.key,
  });

  final Map<String, dynamic> user;
  final VoidCallback onSignOut;

  @override
  Widget build(BuildContext context) => PageFrame(
        title: 'Account & security',
        subtitle: 'Review your account and sign out securely.',
        child: Column(
          children: [
            Card(
              child: ListTile(
                leading: const CircleAvatar(
                  backgroundColor: Color(0xFF16436A),
                  child: Icon(Icons.person_outline, color: Colors.white),
                ),
                title: Text(user['username'] as String),
                subtitle: Text('Role: ${user['role']}'),
                trailing: const Icon(Icons.verified_user_outlined, color: mint),
              ),
            ),
            const Card(
              child: ListTile(
                leading: Icon(Icons.lock_outline, color: blue),
                title: Text('Password protection'),
                subtitle:
                    Text('Passwords are stored as salted, one-way hashes.'),
              ),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                onPressed: onSignOut,
                icon: const Icon(Icons.logout),
                label: const Text('Sign out'),
              ),
            ),
            const SizedBox(height: 14),
            const Text(
              'Messages are not end-to-end encrypted. Use a reviewed secure messenger for confidential communication.',
              style:
                  TextStyle(color: Colors.white38, fontSize: 11, height: 1.5),
            ),
          ],
        ),
      );
}

void showMessage(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message)));
}
