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

struct Nonce {
    let sha:String
    let raw:String
}
protocol SecureNonceProviding {
    func generateNonce() -> Nonce
}
protocol AuthController {
    func authenticate()
}

class SecureNonceProvider : SecureNonceProviding {
    func generateNonce() -> Nonce {
        let randomString = randomNonceString()
        let nonce = Nonce(sha: sha256(randomString), raw: randomString)
        return nonce
    }
    
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


class AppleSignInControllerAuthAdapter:AuthController {
    let appleSignIncontroller:AppleSignInController
    let secureNonceProvider:SecureNonceProviding

    init(appleSignIncontroller: AppleSignInController, secureNonceProvider: SecureNonceProviding) {
        self.appleSignIncontroller = appleSignIncontroller
        self.secureNonceProvider = secureNonceProvider
    }
    
    func authenticate() {
        let nonce = secureNonceProvider.generateNonce()
        let request = makerequest(nonce: nonce.sha)
        let controller = ASAuthorizationController(authorizationRequests: [request])
        appleSignIncontroller.authenticate(controller: controller,nonce:nonce.raw)
    }
    
    func makerequest(nonce:String) -> ASAuthorizationAppleIDRequest{
        let request = ASAuthorizationAppleIDProvider().createRequest()
        request.requestedScopes = [.email,.fullName]
        request.nonce = nonce
        return request
    }
    
    
    
}



class AppleSignInController:NSObject{
   
    private let authSubject = PassthroughSubject<ASAuthorization,AuthError>()
    var currentNonce:String?
    var authPublisher:AnyPublisher<ASAuthorization,AuthError>{
        return authSubject.eraseToAnyPublisher()
    }
    
   
    func authenticate(controller:ASAuthorizationController,nonce:String) {
        controller.delegate = self
        controller.performRequests()
//        currentNonce = nonce
        
    }
   
    
}
 
protocol Credentials {
    var identityToken: Data? { get }
}
extension ASAuthorizationAppleIDCredential:Credentials{}
extension AppleSignInController:ASAuthorizationControllerDelegate{
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        guard let error = error as? ASAuthorizationError else {
            return
        }
        
        authSubject.send(completion:.failure(.underlyingError(error)))
    }
    
    func didComplete(with credentials:Credentials){
        
            guard let appleIDToken = credentials.identityToken,
             let idTokenString = String(data:appleIDToken,encoding: .utf8),
             let currentNonce = currentNonce
       
        else{
            authSubject.send(completion: .failure(.invalidCredentials))
            return
        }
        
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
         let appleIDCredential = authorization.credential as? Credentials
         appleIDCredential.map(didComplete)
    }
}
