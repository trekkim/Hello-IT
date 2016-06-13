//
//  HITPHTTPSFingerprint.m
//  HTTPSFingerprint
//
//  Created by Yoann Gini on 09/05/2016.
//  Copyright © 2016 Yoann Gini. All rights reserved.
//

#import "HITPHTTPSFingerprint.h"
#import <asl.h>
#import <CommonCrypto/CommonCrypto.h>

#define kHTTPSFingerprintURL @"URL"
#define kHTTPSFingerprintReferenceValue @"fingerprint"
#define kHTTPSFingerprintReferenceType @"type"

@interface HITPHTTPSFingerprint () <NSURLSessionDelegate>
@property NSURL *target;
@property NSString *fingerprint;
@property NSString *type;
@end

@implementation HITPHTTPSFingerprint

- (instancetype)initWithSettings:(NSDictionary*)settings
{
    self = [super initWithSettings:settings];
    if (self) {
        _target = [NSURL URLWithString:[settings objectForKey:kHTTPSFingerprintURL]];
        _fingerprint = [settings objectForKey:kHTTPSFingerprintReferenceValue];
        _type = [settings objectForKey:kHTTPSFingerprintReferenceType];
        self.testState = HITPluginTestStateUnavailable;
    }
    return self;
}

- (void)mainAction:(id)sender {
    asl_log(NULL, NULL, ASL_LEVEL_INFO, "Requesting certificate for %s", [[self.target absoluteString] cStringUsingEncoding:NSUTF8StringEncoding]);
    
    
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:self.target completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
    }];
    
    [task resume];
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        SecTrustResultType trustResultType;
        SecTrustEvaluate(serverTrust, &trustResultType);
        
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, (SecTrustGetCertificateCount(serverTrust) - 1));
        NSData *data = CFBridgingRelease(SecCertificateCopyData(certificate));
        
        NSUInteger length = 0;
        
        if ([[self.type lowercaseString] isEqualToString:@"md5"]) {
            length = CC_MD5_DIGEST_LENGTH;
        } else if ([[self.type lowercaseString] isEqualToString:@"sha1"]) {
            length = CC_SHA1_DIGEST_LENGTH;
        } else if ([[self.type lowercaseString] isEqualToString:@"sha256"]) {
            length = CC_SHA256_DIGEST_LENGTH;
        } else if ([[self.type lowercaseString] isEqualToString:@"sha512"]) {
            length = CC_SHA512_DIGEST_LENGTH;
        } else {
            asl_log(NULL, NULL, ASL_LEVEL_ERR, "Unsupported fingerprint type %s", [self.type cStringUsingEncoding:NSUTF8StringEncoding]);
            return;
        }
        
        unsigned char buffer[length];
        
        if ([[self.type lowercaseString] isEqualToString:@"md5"]) {
            CC_MD5(data.bytes, (CC_LONG)data.length, buffer);
        } else if ([[self.type lowercaseString] isEqualToString:@"sha1"]) {
            CC_SHA1(data.bytes, (CC_LONG)data.length, buffer);
        } else if ([[self.type lowercaseString] isEqualToString:@"sha256"]) {
            CC_SHA256(data.bytes, (CC_LONG)data.length, buffer);
        } else if ([[self.type lowercaseString] isEqualToString:@"sha512"]) {
            CC_SHA512(data.bytes, (CC_LONG)data.length, buffer);
        }
        
        NSMutableString *fingerprint = [NSMutableString stringWithCapacity:length * 3];
        
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                [fingerprint appendFormat:@":"];
            }
            [fingerprint appendFormat:@"%02x",buffer[i]];
        }
        
        NSString *finalFingerprint = [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

        if ([finalFingerprint isEqualToString:self.fingerprint]) {
            self.testState = HITPluginTestStateOK;
        } else {
            self.testState = HITPluginTestStateError;
        }
    }
}

@end

