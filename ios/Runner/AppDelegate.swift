import UIKit
import Flutter
import CommonCrypto
import Foundation

enum ChannelName {
  static let crypto = "de.fluttercrypto/crypto"
}

enum MyFlutterErrorCode {
  static let unavailable = "UNAVAILABLE"
}

@UIApplicationMain
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
      
    let controller = window?.rootViewController as! FlutterViewController
    let cryptoChannel = FlutterMethodChannel(
          name: ChannelName.crypto,
          binaryMessenger: controller.binaryMessenger)
      
    GeneratedPluginRegistrant.register(with: self)
      
      cryptoChannel.setMethodCallHandler({
            (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
            switch call.method {

            case "aesCbcEnc":
              guard let args = call.arguments as? [String: String] else { return }
              let password = args["password"]!
              let iterationsString: String? = args["iterations"]
              let plaintext: String? = args["plaintext"]
              if plaintext == nil { result("") }
              if iterationsString == nil { result("")}
              let salt = CC.generateRandom(32)
              let keyByteCount = 32  // AES256
              var rounds = Int(iterationsString!) ?? 0
              if rounds < 10000 {rounds = 10000} // minimum
              let encryptionKey = pbkdf2(
                password: password, saltData: salt, keyByteCount: keyByteCount,
                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
              let aesKey = encryptionKey!
              let iv = CC.generateRandom(16)
              let plainData = plaintext!.data(using: String.Encoding.utf8)!
              let e = try? CC.crypt(.encrypt, blockMode: .cbc, algorithm: .aes, padding: .pkcs7Padding, data: plainData, key: aesKey, iv: iv)
              let eB64: String = (e?.base64EncodedString())!
              let ivB64: String = iv.base64EncodedString()
              let saltB64: String = salt.base64EncodedString()
              let cComplete = saltB64 + ":" + ivB64 + ":" + eB64
              result("\(cComplete)")

            case "aesCbcDec":
              guard let args = call.arguments as? [String: String] else { return }
              let password = args["password"]!
              let completeCiphertext: String? = args["ciphertext"]
              if completeCiphertext == nil { result("") }
              // split ciphertext
              let parts = completeCiphertext!.components(separatedBy: ":")
              let salt = parts[0].base64Decoded
              let iterationsString = parts[1]
              let iv = parts[2].base64Decoded
              let ciphertext = parts[3].base64Decoded
              let keyByteCount = 32  // AES256
              var rounds = Int(iterationsString) ?? 0
              if rounds < 10000 {rounds = 10000} // minimum
              //let rounds = 10001
              let encryptionKey = pbkdf2(
                password: password, saltData: salt!, keyByteCount: keyByteCount,
                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
              let aesKey = encryptionKey!
              let d = try? CC.crypt(.decrypt, blockMode: .cbc, algorithm: .aes, padding: .pkcs7Padding, data: ciphertext!, key: aesKey, iv: iv!)
              let decryptedtext = String(decoding: d!, as: UTF8.self)
              result("\(decryptedtext)")

            case "aesGcmEnc":
              guard let args = call.arguments as? [String: String] else { return }
              let password = args["password"]!
              let iterationsString: String? = args["iterations"]
              let plaintext: String? = args["plaintext"]
              if plaintext == nil { result("") }
              if iterationsString == nil { result("")}
              let salt = CC.generateRandom(32)
              let keyByteCount = 32  // AES256
              var rounds = Int(iterationsString!) ?? 0
              if rounds < 10000 {rounds = 10000} // minimum
              let encryptionKey = pbkdf2(
                password: password, saltData: salt, keyByteCount: keyByteCount,
                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
              let aesKey = encryptionKey!
              let iv = CC.generateRandom(12)
              let plainData = plaintext!.data(using: String.Encoding.utf8)!
              let e = try? CC.cryptAuth(
                .encrypt, blockMode: .gcm, algorithm: .aes, data: plainData, aData: Data(), key: aesKey,
                iv: iv, tagLength: 16)
              let eB64: String = (e?.base64EncodedString())!
              let ivB64: String = iv.base64EncodedString()
              let saltB64: String = salt.base64EncodedString()
              let cComplete = saltB64 + ":" + ivB64 + ":" + eB64
              result("\(cComplete)")

            case "aesGcmDec":
              guard let args = call.arguments as? [String: String] else { return }
              let password = args["password"]!
              let completeCiphertext: String? = args["ciphertext"]
              if completeCiphertext == nil { result("") }
              // split ciphertext
              let parts = completeCiphertext!.components(separatedBy: ":")
              let salt = parts[0].base64Decoded
              let iterationsString = parts[1]
              let iv = parts[2].base64Decoded
              let ciphertext = parts[3].base64Decoded
              let keyByteCount = 32  // AES256
              var rounds = Int(iterationsString) ?? 0
              if rounds < 10000 {rounds = 10000} // minimum
              //let rounds = 10001
              let encryptionKey = pbkdf2(
                password: password, saltData: salt!, keyByteCount: keyByteCount,
                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
              let aesKey = encryptionKey!
              let d = try? CC.cryptAuth(
                .decrypt, blockMode: .gcm, algorithm: .aes, data: ciphertext!, aData: Data(), key: aesKey,
                iv: iv!, tagLength: 16)
              let decryptedtext = String(decoding: d!, as: UTF8.self)
              result("\(decryptedtext)")
                
            case "getCryptEncStringOld":
              guard let args = call.arguments as? [String: String] else { return }
              let password = args["password"]!
              let plaintext: String? = args["plaintext"]
              if plaintext == nil { result("") }
              print("PBKDF2 SHA256 using CommonCrypto")
              let salt = CC.generateRandom(32)
              let keyByteCount = 32  // AES256
              let rounds = 10001
              let encryptionKey = pbkdf2(
                password: password, saltData: salt, keyByteCount: keyByteCount,
                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
              print("encryptionKey: " + encryptionKey!.hexEncodedString())
              print()
              print("AES GCM")
              let aesKey = encryptionKey!
              let iv = CC.generateRandom(12)
              let plainData = plaintext!.data(using: String.Encoding.utf8)!
              print("p: " + plainData.hexEncodedString())
              let testData = "This is a test string".data(using: String.Encoding.utf8)!
              let e = try? CC.cryptAuth(
                .encrypt, blockMode: .gcm, algorithm: .aes, data: plainData, aData: Data(), key: aesKey,
                iv: iv, tagLength: 16)
              print("e: " + (e?.hexEncodedString())!)
              let eB64: String = (e?.base64EncodedString())!
              let ivB64: String = iv.base64EncodedString()
              let saltB64: String = salt.base64EncodedString()

              let cComplete = saltB64 + ":" + rounds.string + ":" + ivB64 + ":" + eB64
              print("cComplete: " + cComplete)
              result("\(cComplete)")

            case "getCryptDecStringOld":
              guard let args = call.arguments as? [String: String] else { return }
              let password = args["password"]!
              let completeCiphertext: String? = args["ciphertext"]
              if completeCiphertext == nil { result("") }
              // split ciphertext

              let parts = completeCiphertext!.components(separatedBy: ":")
              let salt = parts[0].base64Decoded
              // let rounds = parts[1] // string to int conversion
              let iv = parts[2].base64Decoded
              let ciphertext = parts[3].base64Decoded

              print("PBKDF2 SHA256 using CommonCrypto")
              let keyByteCount = 32  // AES256
              let rounds = 10001
              let encryptionKey = pbkdf2(
                password: password, saltData: salt!, keyByteCount: keyByteCount,
                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
              print("encryptionKey: " + encryptionKey!.hexEncodedString())

              print()
              print("AES GCM")
              let aesKey = encryptionKey!
              let d = try? CC.cryptAuth(
                .decrypt, blockMode: .gcm, algorithm: .aes, data: ciphertext!, aData: Data(), key: aesKey,
                iv: iv!, tagLength: 16)
              let decryptedtext = String(decoding: d!, as: UTF8.self)
              result("\(decryptedtext)")
            
            
            case "getCryptString":
              guard let args = call.arguments as? [String: String] else { return }
              let name = args["name"]!
              let gender = args["gender"]!

              print("PBKDF2 SHA256 using CommonCrypto")
              let password = "password"
              let salt = Data(_: [0x73, 0x61, 0x6c, 0x74, 0x44, 0x61, 0x74, 0x61])
              let keyByteCount = 32  // AES256
              let rounds = 10001
              let encryptionKey = pbkdf2(
                password: password, saltData: salt, keyByteCount: keyByteCount,
                prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
              print("encryptionKey: " + encryptionKey!.hexEncodedString())

              print("generate random number")
              let randomData = try! secureRandomData(count: 32)
              print("random: " + randomData.hexEncodedString())

              print()
              print("AES GCM")
              let aesKey = CC.generateRandom(32)
              let iv = CC.generateRandom(12)
              let testData = "This is a test string".data(using: String.Encoding.utf8)!
              print("p: " + testData.hexEncodedString())

              let e = try? CC.cryptAuth(
                .encrypt, blockMode: .gcm, algorithm: .aes, data: testData, aData: Data(), key: aesKey,
                iv: iv, tagLength: 8)

              print("e: " + (e?.hexEncodedString())!)

              let d = try? CC.cryptAuth(
                .decrypt, blockMode: .gcm, algorithm: .aes, data: e!, aData: Data(), key: aesKey, iv: iv,
                tagLength: 8)

              print("d: " + (d?.hexEncodedString())!)

              let eB64: String = (e?.base64EncodedString())!
              let ivB64: String = iv.base64EncodedString()
              let saltB64: String = salt.base64EncodedString()

              let cComplete = saltB64 + ":" + rounds.string + ":" + ivB64 + ":" + eB64
              print("cComplete: " + cComplete)
              result("\(name) encrypts SwCrypt to \(cComplete)")

            default:
              result(FlutterMethodNotImplemented)
            }

          })
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}

func secureRandomData(count: Int) throws -> Data {
  var bytes = [Int8](repeating: 0, count: count)

  // Fill bytes with secure random data
  let status = SecRandomCopyBytes(
    kSecRandomDefault,
    count,
    &bytes
  )

  // A status of errSecSuccess indicates success
  if status == errSecSuccess {
    // Convert bytes to Data
    let data = Data(bytes: bytes, count: count)
    return data
  } else {
    // Handle error
    return Data(_: [0x0])
  }
}

private func pbkdf2(
  password: String, saltData: Data, keyByteCount: Int, prf: CCPseudoRandomAlgorithm, rounds: Int
) -> Data? {
  guard let passwordData = password.data(using: .utf8) else { return nil }
  var derivedKeyData = Data(repeating: 0, count: keyByteCount)
  let derivedCount = derivedKeyData.count
  let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
    let keyBuffer: UnsafeMutablePointer<UInt8> =
      derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
    return saltData.withUnsafeBytes { saltBytes -> Int32 in
      let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(
        to: UInt8.self)
      return CCKeyDerivationPBKDF(
        CCPBKDFAlgorithm(kCCPBKDF2),
        password,
        passwordData.count,
        saltBuffer,
        saltData.count,
        prf,
        UInt32(rounds),
        keyBuffer,
        derivedCount)
    }
  }
  return derivationStatus == kCCSuccess ? derivedKeyData : nil
}

extension StringProtocol {
  var data: Data { Data(utf8) }
  var base64Encoded: Data { data.base64EncodedData() }
  var base64Decoded: Data? { Data(base64Encoded: string) }
}
extension LosslessStringConvertible {
  var string: String { .init(self) }
}
extension Sequence where Element == UInt8 {
  var data: Data { .init(self) }
  var base64Decoded: Data? { Data(base64Encoded: data) }
  var string: String? { String(bytes: self, encoding: .utf8) }
}

extension Data {
  func hexEncodedString() -> String {
    return map { String(format: "%02hhx", $0) }.joined()
  }
}

