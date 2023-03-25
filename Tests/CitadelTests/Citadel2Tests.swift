import Crypto
import BigInt
import NIO
import XCTest
import Logging
import Citadel
import NIOSSH

final class Citadel2Tests: XCTestCase {
    func withDisconnectTest(perform: (SSHServer, SSHClient) async throws -> ()) async throws {
        struct AuthDelegate: NIOSSHServerUserAuthenticationDelegate {
            let password: String
            
            var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
                .password
            }
            
            func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
                switch request.request {
                case .password(.init(password: password)):
                    responsePromise.succeed(.success)
                default:
                    responsePromise.succeed(.failure)
                }
            }
        }
        
        actor CloseHelper {
            var isClosed = false
            
            func close() {
                isClosed = true
            }
        }
        
        let hostKey = NIOSSHPrivateKey(p521Key: .init())
        let password = UUID().uuidString
        
        let server = try await SSHServer.host(
            host: "0.0.0.0",
            port: 2345,
            hostKeys: [
                hostKey
            ],
            authenticationDelegate: AuthDelegate(password: password)
        )
        
        let client = try await SSHClient.connect(
            host: "127.0.0.1",
            port: 2345,
            authenticationMethod: .passwordBased(
                username: "test",
                password: password
            ),
            hostKeyValidator: .trustedKeys([hostKey.publicKey]),
            reconnect: .never
        )
        
        XCTAssertTrue(client.isConnected, "Client is not active")
        
        let helper = CloseHelper()
        client.onDisconnect {
            Task {
                await helper.close()
            }
        }
        
        // Make an exec call that's not handled
        _ = try? await client.executeCommand("test")
        
        try await perform(server, client)
        
        if #available(macOS 13, *) {
            try await Task.sleep(for: .seconds(1))
        } else {
            sleep(1)
        }
        
        let isClosed = await helper.isClosed
        XCTAssertTrue(isClosed, "Connection did not close")
    }
    
    func testOnDisconnectClient() async throws {
        try await withDisconnectTest { server, client in
            try await client.close()
        }
    }
}
