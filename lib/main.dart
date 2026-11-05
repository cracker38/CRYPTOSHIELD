import 'dart:convert';
import 'package:flutter/material.dart';

void main() => runApp(const CryptoShieldApp());

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
        colorScheme: ColorScheme.fromSeed(seedColor: blue, brightness: Brightness.dark),
        useMaterial3: true,
        cardTheme: CardThemeData(color: panel, elevation: 0, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18))),
        inputDecorationTheme: InputDecorationTheme(
          filled: true, fillColor: const Color(0xFF0C1929),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: BorderSide.none),
          focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: const BorderSide(color: blue)),
        ),
      ),
      home: const MainShell(),
    );
  }
}

class MainShell extends StatefulWidget {
  const MainShell({super.key});
  @override
  State<MainShell> createState() => _MainShellState();
}
class _MainShellState extends State<MainShell> {
  int index = 0;
  final pages = const [HomePage(), MessagesPage(), AnalyzerPage(), LabPage(), InvestigationsPage(), ProfilePage()];
  final labels = const ['Home','Messages','Analyzer','Cyber Lab','Cases','Profile'];
  final icons = const [Icons.grid_view_rounded, Icons.forum_outlined, Icons.manage_search, Icons.science_outlined, Icons.fact_check_outlined, Icons.person_outline];
  @override
  Widget build(BuildContext context) => Scaffold(
    body: SafeArea(child: IndexedStack(index: index, children: pages)),
    bottomNavigationBar: NavigationBar(
      backgroundColor: const Color(0xFF0B1726), selectedIndex: index,
      onDestinationSelected: (v) => setState(() => index = v),
      destinations: List.generate(labels.length, (i) => NavigationDestination(icon: Icon(icons[i]), label: labels[i])),
    ),
  );
}

class PageFrame extends StatelessWidget {
  final String title, subtitle;
  final Widget child;
  const PageFrame({super.key, required this.title, required this.subtitle, required this.child});
  @override
  Widget build(BuildContext context) => CustomScrollView(slivers: [
    SliverPadding(padding: const EdgeInsets.fromLTRB(20, 18, 20, 24), sliver: SliverList(delegate: SliverChildListDelegate([
      Row(children: [
        Container(width: 42, height: 42, decoration: BoxDecoration(color: blue.withOpacity(.14), borderRadius: BorderRadius.circular(13)), child: const Icon(Icons.shield_moon_outlined, color: blue)),
        const SizedBox(width: 12),
        const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('CRYPTOSHIELD AI', style: TextStyle(fontSize: 12, letterSpacing: 1.5, color: blue, fontWeight: FontWeight.w800)),
          Text('Security workspace', style: TextStyle(fontSize: 11, color: Colors.white54)),
        ])),
        const Icon(Icons.notifications_none_rounded, color: Colors.white70),
      ]),
      const SizedBox(height: 26),
      Text(title, style: const TextStyle(fontSize: 27, fontWeight: FontWeight.w800, letterSpacing: -.6)),
      const SizedBox(height: 5),
      Text(subtitle, style: const TextStyle(color: Colors.white60, height: 1.4)),
      const SizedBox(height: 22),
      child,
    ]))),
  ]);
}

Widget sectionTitle(String text, {String? trailing}) => Padding(
  padding: const EdgeInsets.only(bottom: 12, top: 8),
  child: Row(children: [Expanded(child: Text(text, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700))), if (trailing != null) Text(trailing, style: const TextStyle(color: blue, fontSize: 12))]),
);
Widget metric(String label, String value, IconData icon, Color color) => Expanded(child: Card(child: Padding(
  padding: const EdgeInsets.all(14), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Icon(icon, color: color, size: 20), const SizedBox(height: 13),
    Text(value, style: const TextStyle(fontSize: 21, fontWeight: FontWeight.w800)),
    Text(label, style: const TextStyle(fontSize: 11, color: Colors.white60)),
  ]),
)));
Widget featureTile(IconData icon, String title, String desc, Color color, {VoidCallback? onTap}) => Card(
  child: ListTile(onTap: onTap, contentPadding: const EdgeInsets.symmetric(horizontal: 15, vertical: 7),
    leading: Container(width: 42, height: 42, decoration: BoxDecoration(color: color.withOpacity(.13), borderRadius: BorderRadius.circular(13)), child: Icon(icon, color: color)),
    title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
    subtitle: Text(desc, style: const TextStyle(color: Colors.white60, fontSize: 12)),
    trailing: const Icon(Icons.chevron_right, color: Colors.white38),
  ),
);

class HomePage extends StatelessWidget {
  const HomePage({super.key});
  @override
  Widget build(BuildContext context) => PageFrame(title: 'Security overview', subtitle: 'Your communication and analysis workspace at a glance.', child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Card(child: Container(width: double.infinity, padding: const EdgeInsets.all(18), decoration: BoxDecoration(borderRadius: BorderRadius.circular(18), gradient: const LinearGradient(colors: [Color(0xFF12385A), Color(0xFF17233E)])), child: const Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [Icon(Icons.verified_user_outlined, color: mint), SizedBox(width: 8), Text('LOCAL DEMO MODE', style: TextStyle(color: mint, fontWeight: FontWeight.w800, letterSpacing: 1))]),
      SizedBox(height: 12), Text('Take control of your digital security.', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800)),
      SizedBox(height: 7), Text('Explore encrypted communication, inspect authorized samples and practice cryptography safely.', style: TextStyle(color: Colors.white70, height: 1.4)),
    ]))),
    const SizedBox(height: 12),
    Row(children: [metric('Active conversations', '0', Icons.forum_outlined, blue), const SizedBox(width: 10), metric('Analysis jobs', '0', Icons.manage_search, mint)]),
    Row(children: [metric('Open investigations', '0', Icons.policy_outlined, Colors.orange), const SizedBox(width: 10), metric('Security alerts', '0', Icons.notifications_active_outlined, Colors.purpleAccent)]),
    sectionTitle('Security workspace', trailing: '6 MODULES'),
    featureTile(Icons.lock_outline, 'Secure messaging', 'Private conversations and device identity', blue),
    featureTile(Icons.biotech_outlined, 'Cipher intelligence', 'Identify formats and assess observable risks', mint),
    featureTile(Icons.school_outlined, 'Cryptography lab', 'Practice with deliberately weak training samples', Colors.orange),
    featureTile(Icons.manage_search, 'Defensive investigations', 'Document authorized analysis and evidence', Colors.purpleAccent),
    const SizedBox(height: 8),
    const Text('Production readiness', style: TextStyle(fontWeight: FontWeight.w700)),
    const SizedBox(height: 7),
    const Text('This starter is a user-interface prototype. Connect the backend, vetted end-to-end encryption protocol, authentication and secure key management before handling real confidential messages.', style: TextStyle(color: Colors.white60, fontSize: 12, height: 1.5)),
  ]));
}

class MessagesPage extends StatefulWidget { const MessagesPage({super.key}); @override State<MessagesPage> createState()=>_MessagesPageState(); }
class _MessagesPageState extends State<MessagesPage> {
  final controller = TextEditingController();
  final List<String> messages = ['Welcome to CRYPTOSHIELD AI demo messaging.'];
  @override void dispose(){controller.dispose();super.dispose();}
  @override Widget build(BuildContext context)=>PageFrame(title:'Secure messages',subtitle:'Conversation interface prototype. Messages are not end-to-end encrypted in this demo.',child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
    Card(child: Padding(padding: const EdgeInsets.all(14), child: Row(children:[const Icon(Icons.info_outline,color:Colors.orange),const SizedBox(width:10),const Expanded(child:Text('Demo only — do not send secrets or sensitive personal information.',style:TextStyle(fontSize:12,color:Colors.white70)))]))),
    sectionTitle('Demo conversation'),
    ...messages.map((m)=>Align(alignment:Alignment.centerRight,child:Container(margin:const EdgeInsets.only(bottom:9),padding:const EdgeInsets.all(13),constraints:const BoxConstraints(maxWidth:300),decoration:BoxDecoration(color:const Color(0xFF16436A),borderRadius:BorderRadius.circular(15)),child:Text(m)))),
    const SizedBox(height: 8),
    TextField(controller:controller,decoration:InputDecoration(hintText:'Write a demo message...',suffixIcon:IconButton(icon:const Icon(Icons.send,color:blue),onPressed:send))),
    const SizedBox(height:12),
    const Text('Production requirements: audited E2EE protocol, verified identity keys, forward secrecy, encrypted attachments, replay protection and secure device storage.',style:TextStyle(color:Colors.white54,fontSize:12,height:1.5)),
  ]));
  void send(){final t=controller.text.trim();if(t.isEmpty)return;setState(()=>messages.add(t));controller.clear();}
}

class AnalyzerPage extends StatefulWidget { const AnalyzerPage({super.key}); @override State<AnalyzerPage> createState()=>_AnalyzerPageState(); }
class _AnalyzerPageState extends State<AnalyzerPage>{
  final input=TextEditingController(); String? report;
  @override void dispose(){input.dispose();super.dispose();}
  String analyze(String raw){
    final s=raw.trim(); if(s.isEmpty)return 'Enter a sample to analyze.';
    final hex=RegExp(r'^(?:[0-9a-fA-F]{2})+$').hasMatch(s);
    bool b64=false; try{final decoded=base64.decode(base64.normalize(s));b64=decoded.isNotEmpty && base64.encode(decoded).replaceAll('=', '')==s.replaceAll('=', '');}catch(_){}
    final prefix=s.startsWith('Salted__')||s.startsWith('U2FsdGVkX1');
    final lines=<String>[
      'PRELIMINARY FORMAT REPORT',
      'Input length: ${s.length} characters',
      'Hexadecimal-like: ${hex ? "Yes" : "No"}',
      'Base64-like: ${b64 ? "Yes" : "No"}',
      'Recognized OpenSSL salted marker: ${prefix ? "Possible (Base64-decoded marker)" : "Not detected"}',
      '',
      'Interpretation:',
      if(hex) 'The sample matches a hexadecimal character pattern. This is an encoding observation, not proof of encryption.',
      if(b64) 'The sample appears Base64-decodable. Base64 is encoding, not encryption.',
      if(!hex && !b64) 'No basic hexadecimal or Base64 pattern was confidently identified.',
      '',
      'Limitations: ciphertext alone usually cannot reveal the exact algorithm, key, mode or security strength. No decryption or password guessing was attempted.',
      'Next steps: identify the source application, obtain protocol metadata and use an authorized key/configuration for further testing.'
    ];
    return lines.join('\n');
  }
  @override Widget build(BuildContext context)=>PageFrame(title:'Cipher intelligence',subtitle:'Inspect authorized samples for recognizable formats and observable characteristics.',child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
    Card(child:Padding(padding:const EdgeInsets.all(14),child:Row(children:[const Icon(Icons.shield_outlined,color:mint),const SizedBox(width:10),const Expanded(child:Text('Analyze only data you own or are authorized to examine.',style:TextStyle(fontSize:12,color:Colors.white70)))]))),
    sectionTitle('Sample input'),
    TextField(controller:input,minLines:5,maxLines:8,decoration:const InputDecoration(hintText:'Paste Base64, hexadecimal or other authorized sample...')),
    const SizedBox(height:12),
    SizedBox(width:double.infinity,child:FilledButton.icon(onPressed:()=>setState(()=>report=analyze(input.text)),icon:const Icon(Icons.manage_search),label:const Text('Analyze sample'))),
    if(report!=null)...[sectionTitle('Analysis result'),Card(child:Padding(padding:const EdgeInsets.all(15),child:SelectableText(report!,style:const TextStyle(height:1.55,fontSize:12))))],
  ]));
}

class LabPage extends StatefulWidget { const LabPage({super.key}); @override State<LabPage> createState()=>_LabPageState(); }
class _LabPageState extends State<LabPage>{
  final input=TextEditingController(); final shift=TextEditingController(text:'3'); String result='';
  @override void dispose(){input.dispose();shift.dispose();super.dispose();}
  String caesar(String s,int n)=>String.fromCharCodes(s.runes.map((c){if(c>=65&&c<=90)return 65+(c-65-n%26+26)%26;if(c>=97&&c<=122)return 97+(c-97-n%26+26)%26;return c;}));
  @override Widget build(BuildContext context)=>PageFrame(title:'Cryptography lab',subtitle:'Learn encryption concepts through safe, local training exercises.',child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
    Card(child:Padding(padding:const EdgeInsets.all(14),child:Row(children:[const Icon(Icons.school_outlined,color:blue),const SizedBox(width:10),const Expanded(child:Text('Training sandbox — do not use classical ciphers to protect real information.',style:TextStyle(fontSize:12,color:Colors.white70)))]))),
    sectionTitle('Caesar cipher decoder',trailing:'CLASSICAL CIPHER'),
    TextField(controller:input,minLines:2,maxLines:4,decoration:const InputDecoration(hintText:'Enter training ciphertext')),
    const SizedBox(height:10),
    TextField(controller:shift,keyboardType:TextInputType.number,decoration:const InputDecoration(labelText:'Shift amount')),
    const SizedBox(height:12),
    SizedBox(width:double.infinity,child:FilledButton(onPressed:(){final n=int.tryParse(shift.text)??3;setState(()=>result=caesar(input.text,n));},child:const Text('Decode exercise'))),
    if(result.isNotEmpty)Card(child:Padding(padding:const EdgeInsets.all(14),child:SelectableText('Training output: $result'))),
    sectionTitle('More laboratory challenges'),
    featureTile(Icons.key_outlined,'Key management basics','Learn entropy, rotation and safe storage',mint),
    featureTile(Icons.fingerprint,'Hashing vs encryption','Understand one-way hashes and reversible encryption',blue),
    featureTile(Icons.warning_amber,'Weak configuration lab','Explore intentionally insecure test configurations',Colors.orange),
    featureTile(Icons.flag_outlined,'CTF challenge tracks','Planned: guided beginner-to-advanced challenges',Colors.purpleAccent),
  ]));
}

class InvestigationsPage extends StatelessWidget {
  const InvestigationsPage({super.key});
  @override Widget build(BuildContext context)=>PageFrame(title:'Investigations',subtitle:'Manage authorized defensive analysis and preserve evidence integrity.',child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
    Card(child:Padding(padding:const EdgeInsets.all(16),child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[const Icon(Icons.folder_special_outlined,color:blue,size:30),const SizedBox(height:12),const Text('No investigation cases',style:TextStyle(fontSize:17,fontWeight:FontWeight.w700)),const SizedBox(height:6),const Text('Case creation, evidence upload, SHA-256 hashing, chain-of-custody events and signed reports will be connected to the backend.',style:TextStyle(color:Colors.white60,height:1.5,fontSize:12)),const SizedBox(height:14),OutlinedButton.icon(onPressed:()=>ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content:Text('Case management is planned for the backend integration.'))),icon:const Icon(Icons.add),label:const Text('New investigation'))]))),
    sectionTitle('Investigation safeguards'),
    featureTile(Icons.verified_user_outlined,'Authorization record','Document scope and permission before analysis',mint),
    featureTile(Icons.tag,'Evidence integrity','Hash evidence and track every access event',blue),
    featureTile(Icons.history,'Audit trail','Record analyst actions and timestamps',Colors.orange),
  ]));
}

class ProfilePage extends StatelessWidget {
  const ProfilePage({super.key});
  @override Widget build(BuildContext context)=>PageFrame(title:'Profile & security',subtitle:'Manage account security and application preferences.',child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
    const Card(child:ListTile(leading:CircleAvatar(backgroundColor:Color(0xFF16436A),child:Icon(Icons.person_outline,color:Colors.white)),title:Text('Demo analyst'),subtitle:Text('Local prototype account'),trailing:Icon(Icons.verified_user_outlined,color:mint))),
    sectionTitle('Security settings'),
    featureTile(Icons.phonelink_lock,'Trusted devices','Device enrollment and revocation — planned',blue),
    featureTile(Icons.security,'Multi-factor authentication','TOTP / passkey integration — planned',mint),
    featureTile(Icons.vpn_key_outlined,'Key management','Secure key lifecycle and backup — planned',Colors.orange),
    featureTile(Icons.admin_panel_settings_outlined,'Permissions & roles','RBAC policy management — planned',Colors.purpleAccent),
    featureTile(Icons.tune,'Preferences','Notifications, privacy and appearance',blue),
    const SizedBox(height:12),
    const Text('Build 0.1.0 • Prototype • Not approved for production security use',style:TextStyle(color:Colors.white38,fontSize:11)),
  ]));
}
