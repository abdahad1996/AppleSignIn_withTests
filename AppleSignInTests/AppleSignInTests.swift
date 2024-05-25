//
//  AppleSignInTests.swift
//  AppleSignInTests
//
//  Created by macbook abdul on 24/05/2024.
//

import XCTest
@testable import AppleSignIn
import AuthenticationServices

final class AppleSignInControllerTests: XCTestCase {

    func test_authenticate_whenCompleteWithAuthorization(){
        let nonceProvider = dummyNonceProvider()
        let spy = ASAuthorizationController.spy
        var receivedRequests = [ASAuthorizationAppleIDRequest]()
        let sut = AppleSignInController(controllerFactory:{ (requests:[ASAuthorizationAppleIDRequest]) -> ASAuthorizationController  in
            receivedRequests += requests
           return spy
            
        },secureNonceProvider: nonceProvider)
        
        
        
        sut.authenticate()
        
        XCTAssertEqual(receivedRequests.count, 1,"received requests")
        XCTAssertEqual(receivedRequests.first?.requestedScopes, [.email,.fullName])
        XCTAssertEqual(receivedRequests.first?.nonce,nonceProvider.generateNonce())
        XCTAssertTrue(spy.delegate === sut,"sut is delegate")
        XCTAssertEqual(spy.performRequestsCallCount,1, "performace call count")
    }
    
   
    
}

class dummyNonceProvider:SecureNonceProviding {
    var currentNonce:String? {
        "currentNonce"
    }
    
    func generateNonce() -> String {
        "generated nonce"
    }
    
    
}
extension ASAuthorizationController {
    static var spy:Spy{
        let dummyRequest = ASAuthorizationAppleIDProvider().createRequest()
        return Spy(authorizationRequests: [dummyRequest])
    }
    class Spy:ASAuthorizationController{
        private (set) var performRequestsCallCount = 0
        override func performRequests() {
            performRequestsCallCount += 1
        }
    }
}
