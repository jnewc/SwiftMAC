//
//  SwiftMAC.swift
//  SwiftMAC
//
//  Created by Jack Newcombe on 20/09/2020.
//  Copyright © 2020 Jack Newcombe. All rights reserved.
//

import Foundation
import Darwin
#if os(iOS)
import RequiredHeadersIOS
#elseif os(macOS)
import RequiredHeadersMACOS
#endif

public class SwiftMAC {
    
    let rtmSize = MemoryLayout<rt_msghdr>.size
        
    let arpSize = MemoryLayout<sockaddr_inarp>.size
    
    let inSize = MemoryLayout<sockaddr_in>.size
    
    public init() {
        
    }
    
    public func mac(fromIPAddress ipAddress: String) -> String? {
   
        let bufferLength = rtmSize + 200
        
        let rtmPointer = UnsafeMutableRawPointer.allocate(byteCount: bufferLength, alignment: 1)
        memset(rtmPointer, 0, bufferLength)
        let rtm = createRTM(pointer: rtmPointer)
        
        _ = createSin(ipAddress: ipAddress, pointer: rtmPointer)

        let buffer = UnsafeMutableRawPointer.allocate(byteCount: bufferLength, alignment: 1)
        memset(buffer, 0, bufferLength)
        
        let sockfd = socket(AF_ROUTE, SOCK_RAW, 0);
        write(sockfd, rtmPointer, Int(rtm.rtm_msglen))
        
        let n = read(sockfd, buffer, bufferLength);
        _ = close(sockfd)
        
        guard n != 0 else { return nil }
        
        let index = Int(rtmSize + arpSize + 8)
        let bytes = buffer.assumingMemoryBound(to: UInt8.self)
        
        let macAddress = String(format: "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
                                bytes[index + 0],
                                bytes[index + 1],
                                bytes[index + 2],
                                bytes[index + 3],
                                bytes[index + 4],
                                bytes[index + 5])
        
        return macAddress
        
        
    }
    
    func createSin(ipAddress: String, pointer: UnsafeMutableRawPointer) -> sockaddr_in {
        var sin = sockaddr_in()
        
        sin.sin_len = UInt8(inSize)
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_addr.s_addr = inet_addr(ipAddress)
        
        pointer.storeBytes(of: sin, toByteOffset: rtmSize, as: sockaddr_in.self)

        return sin
    }
    
    func createRTM(pointer: UnsafeMutableRawPointer) -> rt_msghdr {
        var rtm =  rt_msghdr()
        rtm.rtm_msglen = u_short(rtmSize + inSize)
        rtm.rtm_version = u_char(RTM_VERSION)
        rtm.rtm_type = u_char(RTM_GET)
        rtm.rtm_addrs = RTA_DST
        rtm.rtm_flags = RTF_LLINFO
        rtm.rtm_pid = 1234
        rtm.rtm_seq = 9999
        
        pointer.storeBytes(of: rtm, as: rt_msghdr.self)
        
        return rtm
    }
}
