import 'dart:convert';
import 'package:flutter/material.dart';
import 'security/identity_vault.dart';
import 'services/crypto_shield_api.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const CryptoShieldApp());
}

const navy = Color(0xFF07111F);
const panel = Color(0xFF101F32);
const blue = Color(0xFF43A5FF);
const mint = Color(0xFF3DDBB1);

class CryptoShieldApp extends StatelessWidget {
  const CryptoShieldApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CRYPTOSHIELD AI',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: navy,
        colorScheme:
            ColorScheme.fromSeed(seedColor: blue, brightness: Brightness.dark),
        useMaterial3: true,
        cardTheme: CardThemeData(
            color: panel,
            elevation: 0,
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(18))),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF0C1929),
          border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(14),
              borderSide: BorderSide.none),
          focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(14),
              borderSide: const BorderSide(color: blue)),
        ),
      ),
      home: const AuthGate(),
    );
  }
}

class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  final api = CryptoShieldApi();
  final vault = IdentityVault();
  AuthSession? session;
  DeviceIdentity? identity;
  String? startupError;
  bool loading = true;

  @override
  void initState() {
    super.initState();
    restoreSession();
  }

  Future<void> restoreSession() async {
    try {
      final saved = await vault.loadSession();
      if (saved != null) {
        final profile = await api.getMe(saved.$1);
        final localIdentity = await vault.loadIdentity(saved.$2);
        if (localIdentity == null ||
            localIdentity.encryptionPublicKey !=
                profile['encryption_public_key'] ||
            localIdentity.signingPublicKey != profile['signing_public_key']) {
          await vault.clearSession();
          startupError =
              'This device does not hold the matching private keys. Log in on the device where this account was created.';
        } else {
          session = AuthSession(
            token: saved.$1,
            user: ApiUser(
              id: profile['id'] as int,
              username: profile['username'] as String,
            ),
          );
          identity = localIdentity;
        }
      }
    } on ApiException catch (error) {
      await vault.clearSession();
      startupError = error.message;
    } catch (error) {
      startupError = 'Could not restore the secure session: $error';
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> onAuthenticated(AuthSession value, DeviceIdentity key) async {
    await vault.saveSession(value.token, value.user.username);
    if (!mounted) return;
    setState(() {
      session = value;
      identity = key;
      startupError = null;
    });
  }

  Future<void> logout() async {
    try {
      final current = session;
      if (current != null) await api.logout(current.token);
    } on ApiException catch (exception) {
      startupError =
          'Could not revoke the server session: ${exception.message}';
    } catch (exception) {
      startupError = 'Could not revoke the server session: $exception';
    } finally {
      await vault.clearSession();
    }
    if (!mounted) return;
    setState(() {
      session = null;
      identity = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    final activeSession = session;
    final activeIdentity = identity;
    if (activeSession != null && activeIdentity != null) {
      return MainShell(
        api: api,
        vault: vault,
        session: activeSession,
        identity: activeIdentity,
        onLogout: logout,
      );
    }
    return AuthPage(
      api: api,
      vault: vault,
      initialError: startupError,
      onAuthenticated: onAuthenticated,
    );
  }
}

class AuthPage extends StatefulWidget {
  const AuthPage({
    super.key,
    required this.api,
    required this.vault,
    required this.onAuthenticated,
    this.initialError,
  });

  final CryptoShieldApi api;
  final IdentityVault vault;
  final String? initialError;
  final Future<void> Function(AuthSession, DeviceIdentity) onAuthenticated;

  @override
  State<AuthPage> createState() => _AuthPageState();
}

class _AuthPageState extends State<AuthPage> {
  final usernameController = TextEditingController();
  final passwordController = TextEditingController();
  bool creatingAccount = false;
  bool busy = false;
  String? error;

  @override
  void initState() {
    super.initState();
    error = widget.initialError;
  }

  @override
  void dispose() {
    usernameController.dispose();
    passwordController.dispose();
    super.dispose();
  }

  Future<void> submit() async {
    final username = usernameController.text.trim();
    final password = passwordController.text;
    if (username.length < 3 || password.length < 12) {
      setState(() => error =
          'Use a username of at least 3 characters and a password of at least 12 characters.');
      return;
    }
    setState(() {
      busy = true;
      error = null;
    });
    try {
      DeviceIdentity key;
      AuthSession result;
      if (creatingAccount) {
        if (await widget.vault.loadIdentity(username) != null) {
          throw const ApiException(
            'This device already has keys for that username. Log in instead.',
          );
        }
        key = await DeviceIdentity.generate();
        await widget.vault.saveIdentity(username, key);
        result = await widget.api.register(
          username: username,
          password: password,
          encryptionPublicKey: key.encryptionPublicKey,
          signingPublicKey: key.signingPublicKey,
        );
      } else {
        result = await widget.api.login(username: username, password: password);
        key = (await widget.vault.loadIdentity(result.user.username)) ??
            (throw const ApiException(
              'This account has no private key on this device. Key recovery is not available; sign in on the device used to create the account.',
            ));
        final profile = await widget.api.getMe(result.token);
        if (key.encryptionPublicKey != profile['encryption_public_key'] ||
            key.signingPublicKey != profile['signing_public_key']) {
          throw const ApiException(
            'The local private keys do not match this account. Messaging has been stopped.',
          );
        }
      }
      await widget.onAuthenticated(result, key);
    } on ApiException catch (exception) {
      if (creatingAccount &&
          (exception.statusCode == 400 || exception.statusCode == 409)) {
        await widget.vault.deleteIdentity(username);
      }
      if (mounted) setState(() => error = exception.message);
    } catch (exception) {
      if (mounted) {
        setState(() => error = 'Could not complete account action: $exception');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        body: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Icon(Icons.shield_moon_outlined,
                        color: blue, size: 52),
                    const SizedBox(height: 16),
                    const Text(
                      'CRYPTOSHIELD AI',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: blue,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.5,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      creatingAccount ? 'Create your account' : 'Sign in',
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        fontSize: 26,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Your device creates and keeps the private keys. The server receives only public keys and encrypted messages.',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.white60, height: 1.5),
                    ),
                    const SizedBox(height: 24),
                    TextField(
                      controller: usernameController,
                      textInputAction: TextInputAction.next,
                      autocorrect: false,
                      decoration: const InputDecoration(labelText: 'Username'),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: passwordController,
                      obscureText: true,
                      onSubmitted: (_) => submit(),
                      decoration: const InputDecoration(
                        labelText: 'Password (12+ characters)',
                      ),
                    ),
                    if (error != null) ...[
                      const SizedBox(height: 12),
                      Text(error!,
                          style: const TextStyle(color: Colors.redAccent)),
                    ],
                    const SizedBox(height: 18),
                    FilledButton(
                      onPressed: busy ? null : submit,
                      child: busy
                          ? const SizedBox(
                              height: 20,
                              width: 20,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : Text(
                              creatingAccount ? 'Create account' : 'Sign in'),
                    ),
                    TextButton(
                      onPressed: busy
                          ? null
                          : () => setState(() {
                                creatingAccount = !creatingAccount;
                                error = null;
                              }),
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
        ),
      );
}

class MainShell extends StatefulWidget {
  const MainShell({
    super.key,
    required this.api,
    required this.vault,
    required this.session,
    required this.identity,
    required this.onLogout,
  });

  final CryptoShieldApi api;
  final IdentityVault vault;
  final AuthSession session;
  final DeviceIdentity identity;
  final VoidCallback onLogout;

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> {
  int index = 0;
  final labels = const [
    'Home',
    'Messages',
    'Analyzer',
    'Cyber Lab',
    'Cases',
    'Profile'
  ];
  final icons = const [
    Icons.grid_view_rounded,
    Icons.forum_outlined,
    Icons.manage_search,
    Icons.science_outlined,
    Icons.fact_check_outlined,
    Icons.person_outline
  ];
  @override
  Widget build(BuildContext context) {
    final pages = [
      const HomePage(),
      MessagesPage(
        api: widget.api,
        vault: widget.vault,
        session: widget.session,
        identity: widget.identity,
      ),
      const AnalyzerPage(),
      const LabPage(),
      const InvestigationsPage(),
      ProfilePage(
          username: widget.session.user.username, onLogout: widget.onLogout),
    ];
    return Scaffold(
      body: SafeArea(child: IndexedStack(index: index, children: pages)),
      bottomNavigationBar: NavigationBar(
        backgroundColor: const Color(0xFF0B1726),
        selectedIndex: index,
        onDestinationSelected: (v) => setState(() => index = v),
        destinations: List.generate(
            labels.length,
            (i) =>
                NavigationDestination(icon: Icon(icons[i]), label: labels[i])),
      ),
    );
  }
}

class PageFrame extends StatelessWidget {
  final String title, subtitle;
  final Widget child;
  const PageFrame(
      {super.key,
      required this.title,
      required this.subtitle,
      required this.child});
  @override
  Widget build(BuildContext context) => CustomScrollView(slivers: [
        SliverPadding(
            padding: const EdgeInsets.fromLTRB(20, 18, 20, 24),
            sliver: SliverList(
                delegate: SliverChildListDelegate([
              Row(children: [
                Container(
                    width: 42,
                    height: 42,
                    decoration: BoxDecoration(
                        color: blue.withOpacity(.14),
                        borderRadius: BorderRadius.circular(13)),
                    child: const Icon(Icons.shield_moon_outlined, color: blue)),
                const SizedBox(width: 12),
                const Expanded(
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                      Text('CRYPTOSHIELD AI',
                          style: TextStyle(
                              fontSize: 12,
                              letterSpacing: 1.5,
                              color: blue,
                              fontWeight: FontWeight.w800)),
                      Text('Security workspace',
                          style:
                              TextStyle(fontSize: 11, color: Colors.white54)),
                    ])),
                const Icon(Icons.notifications_none_rounded,
                    color: Colors.white70),
              ]),
              const SizedBox(height: 26),
              Text(title,
                  style: const TextStyle(
                      fontSize: 27,
                      fontWeight: FontWeight.w800,
                      letterSpacing: -.6)),
              const SizedBox(height: 5),
              Text(subtitle,
                  style: const TextStyle(color: Colors.white60, height: 1.4)),
              const SizedBox(height: 22),
              child,
            ]))),
      ]);
}

Widget sectionTitle(String text, {String? trailing}) => Padding(
      padding: const EdgeInsets.only(bottom: 12, top: 8),
      child: Row(children: [
        Expanded(
            child: Text(text,
                style: const TextStyle(
                    fontSize: 16, fontWeight: FontWeight.w700))),
        if (trailing != null)
          Text(trailing, style: const TextStyle(color: blue, fontSize: 12))
      ]),
    );
Widget metric(String label, String value, IconData icon, Color color) =>
    Expanded(
        child: Card(
            child: Padding(
      padding: const EdgeInsets.all(14),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(icon, color: color, size: 20),
        const SizedBox(height: 13),
        Text(value,
            style: const TextStyle(fontSize: 21, fontWeight: FontWeight.w800)),
        Text(label,
            style: const TextStyle(fontSize: 11, color: Colors.white60)),
      ]),
    )));
Widget featureTile(IconData icon, String title, String desc, Color color,
        {VoidCallback? onTap}) =>
    Card(
      child: ListTile(
        onTap: onTap,
        contentPadding: const EdgeInsets.symmetric(horizontal: 15, vertical: 7),
        leading: Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
                color: color.withOpacity(.13),
                borderRadius: BorderRadius.circular(13)),
            child: Icon(icon, color: color)),
        title: Text(title,
            style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
        subtitle: Text(desc,
            style: const TextStyle(color: Colors.white60, fontSize: 12)),
        trailing: const Icon(Icons.chevron_right, color: Colors.white38),
      ),
    );

class HomePage extends StatelessWidget {
  const HomePage({super.key});
  @override
  Widget build(BuildContext context) => PageFrame(
      title: 'Security overview',
      subtitle: 'Your communication and analysis workspace at a glance.',
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Card(
            child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(18),
                    gradient: const LinearGradient(
                        colors: [Color(0xFF12385A), Color(0xFF17233E)])),
                child: const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(children: [
                        Icon(Icons.verified_user_outlined, color: mint),
                        SizedBox(width: 8),
                        Text('ACCOUNT CONNECTED',
                            style: TextStyle(
                                color: mint,
                                fontWeight: FontWeight.w800,
                                letterSpacing: 1))
                      ]),
                      SizedBox(height: 12),
                      Text('Take control of your digital security.',
                          style: TextStyle(
                              fontSize: 20, fontWeight: FontWeight.w800)),
                      SizedBox(height: 7),
                      Text(
                          'Explore encrypted communication, inspect authorized samples and practice cryptography safely.',
                          style: TextStyle(color: Colors.white70, height: 1.4)),
                    ]))),
        const SizedBox(height: 12),
        Row(children: [
          metric('Active conversations', '0', Icons.forum_outlined, blue),
          const SizedBox(width: 10),
          metric('Analysis jobs', '0', Icons.manage_search, mint)
        ]),
        Row(children: [
          metric(
              'Open investigations', '0', Icons.policy_outlined, Colors.orange),
          const SizedBox(width: 10),
          metric('Security alerts', '0', Icons.notifications_active_outlined,
              Colors.purpleAccent)
        ]),
        sectionTitle('Security workspace', trailing: '6 MODULES'),
        featureTile(Icons.lock_outline, 'Secure messaging',
            'Private conversations and device identity', blue),
        featureTile(Icons.biotech_outlined, 'Cipher intelligence',
            'Identify formats and assess observable risks', mint),
        featureTile(Icons.school_outlined, 'Cryptography lab',
            'Practice with deliberately weak training samples', Colors.orange),
        featureTile(Icons.manage_search, 'Defensive investigations',
            'Document authorized analysis and evidence', Colors.purpleAccent),
        const SizedBox(height: 8),
        const Text('Production readiness',
            style: TextStyle(fontWeight: FontWeight.w700)),
        const SizedBox(height: 7),
        const Text(
            'Messages are encrypted on this device before upload. This prototype does not yet provide forward secrecy, audited protocol guarantees, key recovery or production hosting safeguards.',
            style: TextStyle(color: Colors.white60, fontSize: 12, height: 1.5)),
      ]));
}

class MessagesPage extends StatefulWidget {
  const MessagesPage({
    super.key,
    required this.api,
    required this.vault,
    required this.session,
    required this.identity,
  });

  final CryptoShieldApi api;
  final IdentityVault vault;
  final AuthSession session;
  final DeviceIdentity identity;

  @override
  State<MessagesPage> createState() => _MessagesPageState();
}

class _MessagesPageState extends State<MessagesPage> {
  final recipientController = TextEditingController();
  final messageController = TextEditingController();
  List<ConversationSummary> conversations = [];
  List<(ChatMessage, String)> messages = [];
  PublicIdentity? activeIdentity;
  String? activeRecipient;
  String? activeFingerprint;
  String? trustedFingerprint;
  String? error;
  bool verified = false;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    refreshConversations();
  }

  @override
  void dispose() {
    recipientController.dispose();
    messageController.dispose();
    super.dispose();
  }

  Future<void> refreshConversations() async {
    try {
      final result = await widget.api.getConversations(widget.session.token);
      if (mounted) setState(() => conversations = result);
    } on ApiException catch (exception) {
      if (mounted) setState(() => error = exception.message);
    }
  }

  Future<void> openConversation(String username) async {
    final peer = username.trim();
    if (peer.isEmpty || peer == widget.session.user.username) {
      setState(() => error = 'Enter another registered username.');
      return;
    }
    setState(() {
      busy = true;
      error = null;
      activeRecipient = peer;
      activeIdentity = null;
      activeFingerprint = null;
      trustedFingerprint = null;
      verified = false;
      messages = [];
    });
    try {
      final publicIdentity = await widget.api.getPublicIdentity(
        token: widget.session.token,
        username: peer,
      );
      final canonicalPeer = publicIdentity.username;
      final fingerprint = await EndToEndCrypto.fingerprintForPublicKeys(
        encryptionPublicKey: publicIdentity.encryptionPublicKey,
        signingPublicKey: publicIdentity.signingPublicKey,
      );
      final savedTrust =
          await widget.vault.loadTrustedFingerprint(canonicalPeer);
      await widget.api.createConversation(
        token: widget.session.token,
        username: canonicalPeer,
      );
      if (!mounted) return;
      setState(() {
        activeRecipient = canonicalPeer;
        recipientController.text = canonicalPeer;
        activeIdentity = publicIdentity;
        activeFingerprint = fingerprint;
        trustedFingerprint = savedTrust;
        verified = savedTrust == fingerprint;
      });
      if (savedTrust != fingerprint) {
        await showIdentityVerification(publicIdentity, fingerprint);
      }
      if (verified) await loadMessages();
      await refreshConversations();
    } on ApiException catch (exception) {
      if (mounted) setState(() => error = exception.message);
    } catch (exception) {
      if (mounted) {
        setState(() => error = 'Could not open conversation: $exception');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> showIdentityVerification(
    PublicIdentity peer,
    String fingerprint,
  ) async {
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Text('Verify ${peer.username}'),
        content: SelectableText(
          'Compare this fingerprint with ${peer.username} using a trusted, separate channel (in person or a verified call). Do not trust a fingerprint sent in this chat.\n\n$fingerprint',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Not verified'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('I compared it'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await widget.vault.trustFingerprint(peer.username, fingerprint);
      if (!mounted) return;
      setState(() {
        trustedFingerprint = fingerprint;
        verified = true;
      });
      await loadMessages();
    }
  }

  Future<void> loadMessages() async {
    final peer = activeIdentity;
    final recipient = activeRecipient;
    if (peer == null || recipient == null || !verified) return;
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final encrypted = await widget.api.getMessages(
        token: widget.session.token,
        withUser: recipient,
      );
      final decrypted = <(ChatMessage, String)>[];
      for (final message in encrypted) {
        try {
          final plaintext = await EndToEndCrypto.decrypt(
            envelope: message.ciphertext,
            expectedSender: message.sender,
            recipient: widget.session.user.username,
            senderSigningPublicKey:
                message.sender == widget.session.user.username
                    ? widget.identity.signingPublicKey
                    : peer.signingPublicKey,
            identity: widget.identity,
          );
          decrypted.add((message, plaintext));
        } on FormatException {
          decrypted
              .add((message, '[Could not verify or decrypt this message]'));
        }
      }
      if (mounted) setState(() => messages = decrypted);
    } on ApiException catch (exception) {
      if (mounted) setState(() => error = exception.message);
    } catch (exception) {
      if (mounted) {
        setState(() => error = 'Could not load messages: $exception');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> send() async {
    final text = messageController.text.trim();
    final recipient = activeRecipient;
    final peer = activeIdentity;
    if (text.isEmpty || recipient == null || peer == null || !verified) return;
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final ciphertext = await EndToEndCrypto.encrypt(
        plaintext: text,
        sender: widget.session.user.username,
        recipient: recipient,
        recipientPublicKey: peer.encryptionPublicKey,
        identity: widget.identity,
      );
      await widget.api.sendMessage(
        token: widget.session.token,
        recipient: recipient,
        ciphertext: ciphertext,
      );
      messageController.clear();
      await loadMessages();
    } on ApiException catch (exception) {
      if (mounted) setState(() => error = exception.message);
    } catch (exception) {
      if (mounted) {
        setState(() => error = 'Could not send encrypted message: $exception');
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => PageFrame(
        title: 'Secure messages',
        subtitle: 'Encrypt on this device. The server relays ciphertext only.',
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: const Row(
                  children: [
                    Icon(Icons.verified_user_outlined, color: mint),
                    SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Verify each contact fingerprint out of band before sending sensitive messages.',
                        style: TextStyle(fontSize: 12, color: Colors.white70),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            sectionTitle('Open a conversation'),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: recipientController,
                    autocorrect: false,
                    decoration:
                        const InputDecoration(labelText: 'Recipient username'),
                    onSubmitted: openConversation,
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  onPressed: busy
                      ? null
                      : () => openConversation(recipientController.text),
                  icon: const Icon(Icons.arrow_forward),
                  tooltip: 'Open conversation',
                ),
              ],
            ),
            if (conversations.isNotEmpty) ...[
              sectionTitle('Your conversations'),
              Wrap(
                spacing: 8,
                children: conversations
                    .map(
                      (conversation) => ActionChip(
                        label: Text(conversation.otherUsername),
                        onPressed: busy
                            ? null
                            : () {
                                recipientController.text =
                                    conversation.otherUsername;
                                openConversation(conversation.otherUsername);
                              },
                      ),
                    )
                    .toList(),
              ),
            ],
            if (activeRecipient != null) ...[
              sectionTitle('Conversation with $activeRecipient'),
              if (activeFingerprint != null)
                Card(
                  child: ListTile(
                    leading: Icon(
                      verified ? Icons.verified_user : Icons.warning_amber,
                      color: verified ? mint : Colors.orange,
                    ),
                    title: Text(
                      verified ? 'Identity verified' : 'Identity not verified',
                    ),
                    subtitle: SelectableText(activeFingerprint!),
                    trailing: verified
                        ? null
                        : TextButton(
                            onPressed: activeIdentity == null
                                ? null
                                : () => showIdentityVerification(
                                      activeIdentity!,
                                      activeFingerprint!,
                                    ),
                            child: const Text('Verify'),
                          ),
                  ),
                ),
              if (error != null)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Text(error!,
                      style: const TextStyle(color: Colors.redAccent)),
                ),
              if (busy) const LinearProgressIndicator(),
              ...messages.map(
                (entry) => Align(
                  alignment: entry.$1.sender == widget.session.user.username
                      ? Alignment.centerRight
                      : Alignment.centerLeft,
                  child: Container(
                    margin: const EdgeInsets.only(bottom: 9),
                    padding: const EdgeInsets.all(13),
                    constraints: const BoxConstraints(maxWidth: 300),
                    decoration: BoxDecoration(
                      color: entry.$1.sender == widget.session.user.username
                          ? const Color(0xFF16436A)
                          : panel,
                      borderRadius: BorderRadius.circular(15),
                    ),
                    child: Text(entry.$2),
                  ),
                ),
              ),
              if (verified)
                TextField(
                  controller: messageController,
                  minLines: 1,
                  maxLines: 4,
                  maxLength: 5000,
                  decoration: InputDecoration(
                    hintText: 'Write an encrypted message...',
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.send, color: blue),
                      onPressed: busy ? null : send,
                    ),
                  ),
                  onSubmitted: (_) => send(),
                ),
            ],
          ],
        ),
      );
}

class AnalyzerPage extends StatefulWidget {
  const AnalyzerPage({super.key});
  @override
  State<AnalyzerPage> createState() => _AnalyzerPageState();
}

class _AnalyzerPageState extends State<AnalyzerPage> {
  final input = TextEditingController();
  String? report;
  @override
  void dispose() {
    input.dispose();
    super.dispose();
  }

  String analyze(String raw) {
    final s = raw.trim();
    if (s.isEmpty) return 'Enter a sample to analyze.';
    final hex = RegExp(r'^(?:[0-9a-fA-F]{2})+$').hasMatch(s);
    bool b64 = false;
    try {
      final decoded = base64.decode(base64.normalize(s));
      b64 = decoded.isNotEmpty &&
          base64.encode(decoded).replaceAll('=', '') == s.replaceAll('=', '');
    } catch (_) {}
    final prefix = s.startsWith('Salted__') || s.startsWith('U2FsdGVkX1');
    final lines = <String>[
      'PRELIMINARY FORMAT REPORT',
      'Input length: ${s.length} characters',
      'Hexadecimal-like: ${hex ? "Yes" : "No"}',
      'Base64-like: ${b64 ? "Yes" : "No"}',
      'Recognized OpenSSL salted marker: ${prefix ? "Possible (Base64-decoded marker)" : "Not detected"}',
      '',
      'Interpretation:',
      if (hex)
        'The sample matches a hexadecimal character pattern. This is an encoding observation, not proof of encryption.',
      if (b64)
        'The sample appears Base64-decodable. Base64 is encoding, not encryption.',
      if (!hex && !b64)
        'No basic hexadecimal or Base64 pattern was confidently identified.',
      '',
      'Limitations: ciphertext alone usually cannot reveal the exact algorithm, key, mode or security strength. No decryption or password guessing was attempted.',
      'Next steps: identify the source application, obtain protocol metadata and use an authorized key/configuration for further testing.'
    ];
    return lines.join('\n');
  }

  @override
  Widget build(BuildContext context) => PageFrame(
      title: 'Cipher intelligence',
      subtitle:
          'Inspect authorized samples for recognizable formats and observable characteristics.',
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Card(
            child: Padding(
                padding: const EdgeInsets.all(14),
                child: Row(children: [
                  const Icon(Icons.shield_outlined, color: mint),
                  const SizedBox(width: 10),
                  const Expanded(
                      child: Text(
                          'Analyze only data you own or are authorized to examine.',
                          style:
                              TextStyle(fontSize: 12, color: Colors.white70)))
                ]))),
        sectionTitle('Sample input'),
        TextField(
            controller: input,
            minLines: 5,
            maxLines: 8,
            decoration: const InputDecoration(
                hintText:
                    'Paste Base64, hexadecimal or other authorized sample...')),
        const SizedBox(height: 12),
        SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
                onPressed: () => setState(() => report = analyze(input.text)),
                icon: const Icon(Icons.manage_search),
                label: const Text('Analyze sample'))),
        if (report != null) ...[
          sectionTitle('Analysis result'),
          Card(
              child: Padding(
                  padding: const EdgeInsets.all(15),
                  child: SelectableText(report!,
                      style: const TextStyle(height: 1.55, fontSize: 12))))
        ],
      ]));
}

class LabPage extends StatefulWidget {
  const LabPage({super.key});
  @override
  State<LabPage> createState() => _LabPageState();
}

class _LabPageState extends State<LabPage> {
  final input = TextEditingController();
  final shift = TextEditingController(text: '3');
  String result = '';
  @override
  void dispose() {
    input.dispose();
    shift.dispose();
    super.dispose();
  }

  String caesar(String s, int n) => String.fromCharCodes(s.runes.map((c) {
        if (c >= 65 && c <= 90) return 65 + (c - 65 - n % 26 + 26) % 26;
        if (c >= 97 && c <= 122) return 97 + (c - 97 - n % 26 + 26) % 26;
        return c;
      }));
  @override
  Widget build(BuildContext context) => PageFrame(
      title: 'Cryptography lab',
      subtitle:
          'Learn encryption concepts through safe, local training exercises.',
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Card(
            child: Padding(
                padding: const EdgeInsets.all(14),
                child: Row(children: [
                  const Icon(Icons.school_outlined, color: blue),
                  const SizedBox(width: 10),
                  const Expanded(
                      child: Text(
                          'Training sandbox — do not use classical ciphers to protect real information.',
                          style:
                              TextStyle(fontSize: 12, color: Colors.white70)))
                ]))),
        sectionTitle('Caesar cipher decoder', trailing: 'CLASSICAL CIPHER'),
        TextField(
            controller: input,
            minLines: 2,
            maxLines: 4,
            decoration:
                const InputDecoration(hintText: 'Enter training ciphertext')),
        const SizedBox(height: 10),
        TextField(
            controller: shift,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(labelText: 'Shift amount')),
        const SizedBox(height: 12),
        SizedBox(
            width: double.infinity,
            child: FilledButton(
                onPressed: () {
                  final n = int.tryParse(shift.text) ?? 3;
                  setState(() => result = caesar(input.text, n));
                },
                child: const Text('Decode exercise'))),
        if (result.isNotEmpty)
          Card(
              child: Padding(
                  padding: const EdgeInsets.all(14),
                  child: SelectableText('Training output: $result'))),
        sectionTitle('More laboratory challenges'),
        featureTile(Icons.key_outlined, 'Key management basics',
            'Learn entropy, rotation and safe storage', mint),
        featureTile(Icons.fingerprint, 'Hashing vs encryption',
            'Understand one-way hashes and reversible encryption', blue),
        featureTile(
            Icons.warning_amber,
            'Weak configuration lab',
            'Explore intentionally insecure test configurations',
            Colors.orange),
        featureTile(
            Icons.flag_outlined,
            'CTF challenge tracks',
            'Planned: guided beginner-to-advanced challenges',
            Colors.purpleAccent),
      ]));
}

class InvestigationsPage extends StatelessWidget {
  const InvestigationsPage({super.key});
  @override
  Widget build(BuildContext context) => PageFrame(
      title: 'Investigations',
      subtitle:
          'Manage authorized defensive analysis and preserve evidence integrity.',
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Card(
            child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Icon(Icons.folder_special_outlined,
                          color: blue, size: 30),
                      const SizedBox(height: 12),
                      const Text('No investigation cases',
                          style: TextStyle(
                              fontSize: 17, fontWeight: FontWeight.w700)),
                      const SizedBox(height: 6),
                      const Text(
                          'Case creation, evidence upload, SHA-256 hashing, chain-of-custody events and signed reports will be connected to the backend.',
                          style: TextStyle(
                              color: Colors.white60,
                              height: 1.5,
                              fontSize: 12)),
                      const SizedBox(height: 14),
                      OutlinedButton.icon(
                          onPressed: () => ScaffoldMessenger.of(context)
                              .showSnackBar(const SnackBar(
                                  content: Text(
                                      'Case management is planned for the backend integration.'))),
                          icon: const Icon(Icons.add),
                          label: const Text('New investigation'))
                    ]))),
        sectionTitle('Investigation safeguards'),
        featureTile(Icons.verified_user_outlined, 'Authorization record',
            'Document scope and permission before analysis', mint),
        featureTile(Icons.tag, 'Evidence integrity',
            'Hash evidence and track every access event', blue),
        featureTile(Icons.history, 'Audit trail',
            'Record analyst actions and timestamps', Colors.orange),
      ]));
}

class ProfilePage extends StatelessWidget {
  const ProfilePage(
      {super.key, required this.username, required this.onLogout});
  final String username;
  final VoidCallback onLogout;
  @override
  Widget build(BuildContext context) => PageFrame(
      title: 'Profile & security',
      subtitle: 'Manage account security and application preferences.',
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Card(
            child: ListTile(
                leading: const CircleAvatar(
                    backgroundColor: Color(0xFF16436A),
                    child: Icon(Icons.person_outline, color: Colors.white)),
                title: Text(username),
                subtitle: const Text('Authenticated account'),
                trailing:
                    const Icon(Icons.verified_user_outlined, color: mint))),
        sectionTitle('Security settings'),
        featureTile(Icons.phonelink_lock, 'Trusted devices',
            'Device enrollment and revocation — planned', blue),
        featureTile(Icons.security, 'Multi-factor authentication',
            'TOTP / passkey integration — planned', mint),
        featureTile(Icons.vpn_key_outlined, 'Key management',
            'Secure key lifecycle and backup — planned', Colors.orange),
        featureTile(Icons.admin_panel_settings_outlined, 'Permissions & roles',
            'RBAC policy management — planned', Colors.purpleAccent),
        featureTile(Icons.tune, 'Preferences',
            'Notifications, privacy and appearance', blue),
        const SizedBox(height: 12),
        SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
                onPressed: onLogout,
                icon: const Icon(Icons.logout),
                label: const Text('Sign out'))),
        const Text(
            'Build 0.1.0 • Prototype • Not approved for production security use',
            style: TextStyle(color: Colors.white38, fontSize: 11)),
      ]));
}
