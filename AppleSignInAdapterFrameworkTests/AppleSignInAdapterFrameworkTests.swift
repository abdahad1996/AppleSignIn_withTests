//
//  AppleSignInAdapterFrameworkTests.swift
//  AppleSignInAdapterFrameworkTests
//
//  Created by macbook abdul on 24/05/2024.
//

import XCTest
@testable import AppleSignInAdapterFramework
import AuthenticationServices
import Combine



final class AppleSignInControllerAuthAdapterTests: XCTestCase {
    
    func test_authenticate_performsProperRequests(){
        let nonceProvider = dummyNonceProvider()
        let nonce = nonceProvider.generateNonce()
        let spy = AppleSignInControllerSpy()
        let sut = AppleSignInControllerAuthAdapter(appleSignIncontroller:spy, secureNonceProvider: nonceProvider)
        
        sut.authenticate()
        
       
        XCTAssertEqual(spy.requests.count, 1,"received requests")
        XCTAssertEqual(spy.requests.first?.requestedScopes, [.email,.fullName])
        XCTAssertEqual(spy.requests.first?.nonce,nonce.sha)
        
        
        
    }
}
final class AppleSignInControllerSpy:AppleSignInController{
    var requests = [ASAuthorizationAppleIDRequest]()
    override func authenticate(controller: ASAuthorizationController,nonce:String) {
        requests += controller.authorizationRequests.compactMap{$0 as? ASAuthorizationAppleIDRequest}
    }
}

final class AppleSignInControllerTests: XCTestCase {

    func test_authenticate_whenCompleteWithAuthorization(){
       
        let spy = ASAuthorizationController.spy
        let sut = AppleSignInController()
        
        sut.authenticate(controller: spy, nonce: "any")
        
        XCTAssertTrue(spy.delegate === sut,"sut is delegate")
        XCTAssertEqual(spy.performRequestsCallCount,1, "performace call count")
    }
    
   
    func test_didCompleteWithError_emitsFailure(){
        let sut = AppleSignInController()
        let spy = PublisherSpy(sut.authPublisher)

        sut.authenticate(controller: .spy, nonce: "any nonce")
        sut.authorizationController(controller: .spy, didCompleteWithError: ASAuthorizationError(.failed) as NSError)
        
        XCTAssertEqual(spy.events, [.failure])
        
    }
    
    func test_didCompleteWithAuthorization_withInvalidToken_emitsFailure(){
        let sut = AppleSignInController()
        let spy = PublisherSpy(sut.authPublisher)

        sut.authenticate(controller: .spy, nonce: "any")
        sut.didComplete(with: DummyCredentials(identityToken: nil))
        
        XCTAssertEqual(spy.events, [.failure])
        
    }
    
    func test_didCompleteWithAuthorization_withOutNonce_emitsFailure(){
        let sut = AppleSignInController()
        let spy = PublisherSpy(sut.authPublisher)

        sut.didComplete(with: DummyCredentials(identityToken:  Data("anydata".utf8)))
        
        XCTAssertEqual(spy.events, [.failure])
        
    }
    
    func test_didCompleteWithAuthorization_withValidCredentials_StoresUser(){
        let sut = AppleSignInController()
        let spy = PublisherSpy(sut.authPublisher)

        sut.authenticate(controller: .spy, nonce: "any")
        sut.didComplete(with: DummyCredentials(identityToken:  Data("anydata".utf8)))
        
        XCTAssertEqual(spy.events, [.])
        
    }
    
}
struct DummyCredentials:Credentials{
    let identityToken: Data?
}
class PublisherSpy<Success,Failure:Error>{
    private var cancellable:AnyCancellable?
    private (set) var events = [messages]()
    enum messages {
        case failure
        case finished
        case value
    }
    init(_ publisher:AnyPublisher<Success,Failure>) {
         cancellable = publisher.sink { completion in
             switch completion {
             case .finished:
                 self.events.append(.finished)
             case .failure(let _):
                 self.events.append(.failure)
                 
             }
         } receiveValue: { _ in
             self.events.append(.value)
         }

    }
}
class dummyNonceProvider:SecureNonceProviding {
    
    func generateNonce() -> Nonce {
       return Nonce(sha: "sha string", raw: "raw string")
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
