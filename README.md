# aes_playground_native

AES encryption in modes CBC and GCM using native methods

version 1.0.0

For more information see http://fluttercrypto.bplaced.net/aes-playground-webcrypto/

```plaintext

https://pub.dev/packages/webcrypto
https://github.com/google/webcrypto.dart
webcrypto: ^0.5.2

//uses pointycastle: ^3.3.5 for encryption
//https://pub.dev/packages/pointycastle

uses url_launcher: ^6.0.12 for text-link to fluttercrypto homepage

https://pub.dev/packages/url_launcher

```

appended in AndroidManifest.xml:
```plaintext
    <queries>
        <!-- If your app opens https URLs -->
        <intent>
            <action android:name="android.intent.action.VIEW" />
            <data android:scheme="https" />
        </intent>
    </queries>
```

project is null safety

```plaintext
Flutter 2.5.3 • channel stable • https://github.com/flutter/flutter.git
Framework • revision 18116933e7 (vor 3 Wochen) • 2021-10-15 10:46:35 -0700
Engine • revision d3ea636dc5
Tools • Dart 2.14.4

Android Studio Arctic Fox | 2020.3.1 Patch 3
Build #AI-203.7717.56.2031.7784292, built on October 1, 2021
Runtime version: 11.0.10+0-b96-7249189 aarch64
VM: OpenJDK 64-Bit Server VM by JetBrains s.r.o.
macOS 11.6.1
GC: G1 Young Generation, G1 Old Generation
Memory: 2048M
Cores: 8
Registry: external.system.auto.import.disabled=true
Non-Bundled Plugins: Dart, org.jetbrains.kotlin, io.flutter, org.intellij.plugins.markdown
```

```plaintext
Android Studio Arctic Fox Version 2020.3.1 Patch 3
Build #AI-203.7717.56.2031.7784292
Runtime version: 11.0.10+0-b96-7249189 aarch64
VM: OpenJDK 64-Bit Server VM
Flutter 2.5.3 channel stable Framework Revision 18116933e7
Dart 2.14.4
```

/Users/michaelfehr/flutter/bin/flutter clean

https://www.moncefbelyamani.com/how-to-install-xcode-homebrew-git-rvm-ruby-on-mac/

```plaintext
AES GCM-256 PBKDF2 example

Klartext: Mein wichtiges Geheimnis

Passwort: Passwort1234
```

Ausgabe:

```plaintext
{
  "algorithm": "AES-256 CBC PBKDF2",
  "iterations": "15000",
  "salt": "DDMReRTFCryYjwgUtXQLPQWdWTkdZD+2uHrVv1n4e3Y=",
  "iv": "RthZShR8D1wIawAekH7pTw==",
  "ciphertext": "KQ3RO2VxHvgNKfuY4PF6iOH5BK5iM1m7yx0kQ7l5Dio=",
  "gcmTag": "nicht benutzt"
}
```

```plaintext
{
  "algorithm": "AES-256 GCM PBKDF2",
  "iterations": "15000",
  "salt": "6bcqCf8f3Ah+4/j5FOz2SqQWCc/cGA6PukZQrrlY0lk=",
  "iv": "ZQSqdPS2YZLxqhx5",
  "ciphertext": "bdDog+lCOvPCk8LkDlGajU0VqMwUJEdMRDBNvOi6/0FUTigK73THLA==",
  "gcmTag": "an ciphertext angehängt"
}
```

```plaintext
Tested on Android 11 (SDK 30) Emulator
Android 12 (SDK 31) Emulator
Android 6 (SDK 23) Emulator
Android 5 (SDK 21) Emulator
iOS 15 Emulator
iOS 11.4 Emulator
```

```plaintext

```




## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://flutter.dev/docs/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://flutter.dev/docs/cookbook)

For help getting started with Flutter, view our
[online documentation](https://flutter.dev/docs), which offers tutorials,
samples, guidance on mobile development, and a full API reference.
