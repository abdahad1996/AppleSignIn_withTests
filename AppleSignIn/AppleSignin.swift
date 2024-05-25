//
//  AppleSignin.swift
//  AppleSignIn
//
//  Created by macbook abdul on 24/05/2024.
//

import Foundation
import CryptoKit
import Combine
import AuthenticationServices

protocol SecureNonceProviding {
    var currentNonce:String? {get}
    func generateNonce() -> String
}
protocol AuthController {
    func authenticate()
}

class SecureNonceProvider : SecureNonceProviding {
    var currentNonce: String?
    
    
    func generateNonce() -> String {
        let randomString = randomNonceString()
        currentNonce = randomString
        return sha256(randomString)
    }
    
    
}
extension SecureNonceProviding {
      func randomNonceString(length: Int = 32) -> String {
      precondition(length > 0)
      var randomBytes = [UInt8](repeating: 0, count: length)
      let errorCode = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
      if errorCode != errSecSuccess {
        fatalError(
          "Unable to generate nonce. SecRandomCopyBytes failed with OSStatus \(errorCode)"
        )
      }

      let charset: [Character] =
        Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")

      let nonce = randomBytes.map { byte in
        // Pick a random character from the set, wrapping around if needed.
        charset[Int(byte) % charset.count]
      }

      return String(nonce)
    }
    @available(iOS 13, *)
      func sha256(_ input: String) -> String {
      let inputData = Data(input.utf8)
      let hashedData = SHA256.hash(data: inputData)
      let hashString = hashedData.compactMap {
        String(format: "%02x", $0)
      }.joined()

      return hashString
    }
}
enum AuthError:Error{
    case invalidCredentials
    case underlyingError(ASAuthorizationError)
}
enum AuthState {
    case success
    case error
}


class AppleSignInController:NSObject,AuthController{
    public typealias ControllerFactory = ([ASAuthorizationAppleIDRequest]) -> ASAuthorizationController
    private var secureNonceProvider:SecureNonceProviding
    private let authSubject = PassthroughSubject<ASAuthorization,AuthError>()
    private let controllerFactory:ControllerFactory
    var authPublisher:AnyPublisher<ASAuthorization,AuthError>{
        return authSubject.eraseToAnyPublisher()
    }
    
    init(
        controllerFactory:@escaping ControllerFactory = ASAuthorizationController.init ,
        secureNonceProvider: SecureNonceProviding = SecureNonceProvider()
    ) {
        self.secureNonceProvider = secureNonceProvider
        self.controllerFactory = controllerFactory
    }
    
    func authenticate() {
        let request = makerequest()
        let authController = controllerFactory([request])
        authController.delegate = self
        authController.performRequests()
    }
    
    func makerequest() -> ASAuthorizationAppleIDRequest{
        let request = ASAuthorizationAppleIDProvider().createRequest()
        request.requestedScopes = [.email,.fullName]
        request.nonce = secureNonceProvider.generateNonce()
        return request
    }
    
}
 
extension AppleSignInController:ASAuthorizationControllerDelegate{
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        guard let error = error as? ASAuthorizationError else {
            return
        }
        authSubject.send(completion:.failure(.underlyingError(error)))
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let appleIDCredentials = authorization.credential as? ASAuthorizationAppleIDCredential,
             let appleIDToken = appleIDCredentials.identityToken,
             let idTokenString = String(data:appleIDToken,encoding: .utf8),
             let currentNonce = secureNonceProvider.currentNonce
            
        
        else{
            authSubject.send(completion: .failure(.invalidCredentials))
            return
        }
    }
}
