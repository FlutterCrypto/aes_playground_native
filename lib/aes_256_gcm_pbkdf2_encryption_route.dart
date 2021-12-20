import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class Aes256GcmPbkdf2EncryptionRoute extends StatefulWidget {
  const Aes256GcmPbkdf2EncryptionRoute({Key? key}) : super(key: key);

  final String title = 'GCM Verschlüsselung';

  @override
  _MyFormPageState createState() => _MyFormPageState();
}

class _MyFormPageState extends State<Aes256GcmPbkdf2EncryptionRoute> {
  @override
  void initState() {
    super.initState();
    descriptionController.text = txtDescription;
  }

  static const MethodChannel methodChannel =
  MethodChannel('de.fluttercrypto/crypto');
  String _returnString = 'Return string: unknown';

  final _formKey = GlobalKey<FormState>();
  TextEditingController descriptionController = TextEditingController();

  // the following controller have a default value
  TextEditingController plaintextController = TextEditingController(
      text: 'The quick brown fox jumps over the lazy dog');
  TextEditingController iterationenController =
      TextEditingController(text: '15000');

  TextEditingController passwordController = TextEditingController();
  TextEditingController outputController = TextEditingController();

  String txtDescription = 'AES-256 GCM Verschlüsselung, der Schlüssel'
      ' wird mit PBKDF2 (wählbare Iterationen) von einem Passwort abgeleitet.';

  String _returnJson(String data) {
    var parts = data.split(':');
    var algorithm = parts[0];
    var iterations = parts[1];
    var salt = parts[2];
    var iv = parts[3];
    var ciphertext = parts[4];
    //var gcmTag = parts[5];
    var gcmTag = 'an ciphertext angehängt';

    JsonEncryption jsonEncryption = JsonEncryption(
        algorithm: algorithm,
        iterations: iterations,
        salt: salt,
        iv: iv,
        ciphertext: ciphertext,
        gcmTag: gcmTag);

    String encryptionResult = jsonEncode(jsonEncryption);
    // make it pretty
    var object = json.decode(encryptionResult);
    var prettyEncryptionResult2 = JsonEncoder.withIndent('  ').convert(object);

    return prettyEncryptionResult2;
  }

  Future<void> _aesGcmEncBase64(String password, String iterations, String plaintext) async {
    String returnString;
    final arguments = {'password' : password,
      'iterations' : iterations,
      'plaintext' : plaintext};
    try {
      final String result = await methodChannel.invokeMethod('aesGcmEnc', arguments);
      returnString = '$result';
    } on PlatformException {
      returnString = 'Failed to get return string.';
    }
    setState(() {
      _returnString = returnString;
      outputController.text = returnString;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: SingleChildScrollView(
        child: Form(
          key: _formKey,
          child: Padding(
            padding: const EdgeInsets.all(15),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.start,
              children: <Widget>[
                //SizedBox(height: 20),
                // form description
                TextFormField(
                  controller: descriptionController,
                  keyboardType: TextInputType.text,
                  autocorrect: false,
                  enabled: false,
                  // false = disabled, true = enabled
                  maxLines: 3,
                  decoration: InputDecoration(
                    labelText: 'Beschreibung',
                    border: OutlineInputBorder(),
                  ),
                ),

                SizedBox(height: 20),
                // plaintext
                TextFormField(
                  controller: plaintextController,
                  maxLines: 3,
                  maxLength: 500,
                  keyboardType: TextInputType.multiline,
                  autocorrect: false,
                  decoration: InputDecoration(
                    labelText: 'Klartext',
                    border: OutlineInputBorder(),
                  ),
                  validator: (value) {
                    if (value == null || value.isEmpty) {
                      return 'Bitte Daten eingeben';
                    }
                    return null;
                  },
                ),
                SizedBox(height: 10),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: <Widget>[
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.grey,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () {
                          plaintextController.text = '';
                        },
                        child: Text('Feld löschen'),
                      ),
                    ),
                    SizedBox(width: 15),
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.blue,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () async {
                          final data =
                              await Clipboard.getData(Clipboard.kTextPlain);
                          plaintextController.text = data!.text!;
                        },
                        child: Text('aus Zwischenablage einfügen'),
                      ),
                    ),
                  ],
                ),

                // password
                SizedBox(height: 20),
                TextFormField(
                  controller: passwordController,
                  enabled: true,
                  // false = disabled, true = enabled
                  style: TextStyle(
                    fontSize: 15,
                  ),
                  keyboardType: TextInputType.text,
                  decoration: InputDecoration(
                    labelText: 'Passwort',
                    hintText: 'geben Sie das Passwort zur Verschlüsselung ein',
                    border: OutlineInputBorder(),
                  ),
                  validator: (value) {
                    if (value == null || value.isEmpty) {
                      return 'Bitte Daten eingeben';
                    }
                    return null;
                  },
                ),
                SizedBox(height: 15),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: <Widget>[
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.grey,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () {
                          passwordController.text = '';
                        },
                        child: Text('Feld löschen'),
                      ),
                    ),
                    SizedBox(width: 15),
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.blue,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () async {
                          final data =
                              await Clipboard.getData(Clipboard.kTextPlain);
                          passwordController.text = data!.text!;
                        },
                        child: Text('aus Zwischenablage einfügen'),
                      ),
                    ),
                  ],
                ),

                // iterationen
                SizedBox(height: 20),
                TextFormField(
                  controller: iterationenController,
                  enabled: true,
                  // false = disabled, true = enabled
                  style: TextStyle(
                    fontSize: 15,
                  ),
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: InputDecoration(
                    labelText: 'Iterationen',
                    hintText: 'geben Sie die Anzahl der Iterationen ein',
                    border: OutlineInputBorder(),
                  ),
                  validator: (value) {
                    if (value == null ||
                        value.isEmpty ||
                        int.tryParse(value)! < 10000) {
                      return 'Bitte Daten eingeben (Minimum 10000)';
                    }
                    return null;
                  },
                ),

                SizedBox(height: 20),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: <Widget>[
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.grey,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () {
                          _formKey.currentState!.reset();
                        },
                        child: Text('Formulardaten löschen'),
                      ),
                    ),
                    SizedBox(width: 25),
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.blue,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () async {
                          if (_formKey.currentState!.validate()) {
                            String plaintext = plaintextController.text;
                            String password = passwordController.text;
                            String iterations = iterationenController.text;

                            // aufruf des native code
                            String output = '';
                            await _aesGcmEncBase64(
                                password, iterations, plaintext);
                            output = _returnString;
                            String _formdata = 'AES-256 GCM PBKDF2' +
                                ':' +
                                iterations +
                                ':' +
                                output;
                            String jsonOutput = _returnJson(_formdata);
                            outputController.text = jsonOutput;
                          } else {
                            print("Formular ist nicht gültig");
                          }
                        },
                        child: Text('verschlüsseln'),
                      ),
                    ),
                  ],
                ),
                SizedBox(height: 20),
                TextFormField(
                  controller: outputController,
                  maxLines: 15,
                  maxLength: 500,
                  decoration: InputDecoration(
                    labelText: 'Ausgabe',
                    hintText: 'Ausgabe',
                    border: OutlineInputBorder(),
                  ),
                ),
                SizedBox(height: 10),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: <Widget>[
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.grey,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () {
                          outputController.text = '';
                        },
                        child: Text('Feld löschen'),
                      ),
                    ),
                    SizedBox(width: 15),
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                            primary: Colors.blue,
                            textStyle: TextStyle(color: Colors.white)),
                        onPressed: () async {
                          final data =
                              ClipboardData(text: outputController.text);
                          await Clipboard.setData(data);
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: const Text(
                                  'Daten in die Zwischenablage kopiert'),
                            ),
                          );
                        },
                        child: Text('in Zwischenablage kopieren'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class JsonEncryption {
  JsonEncryption({
    required this.algorithm,
    this.iterations,
    this.salt,
    this.iv,
    required this.ciphertext,
    this.gcmTag,
  });

  final String algorithm;
  final String? iterations;
  final String? salt;
  final String? iv;
  final String ciphertext;
  final String? gcmTag;

  Map toJson() => {
        'algorithm': algorithm,
        'iterations': iterations,
        'salt': salt,
        'iv': iv,
        'ciphertext': ciphertext,
        'gcmTag': gcmTag,
      };
}
