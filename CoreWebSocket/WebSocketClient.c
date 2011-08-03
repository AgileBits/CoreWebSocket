//
//  WebSocketClient.c
//  WebSocketCore
//
//  Created by Mirek Rusin on 07/03/2011.
//  Copyright 2011 Inteliv Ltd. All rights reserved.
//

#include "WebSocketClient.h"

#define DEBUG_WEBSOCKETCLIENT 0


#pragma pack(1)
typedef struct FrameHeader_HYBI_07 {
	unsigned int opcode:4;
	unsigned int rsv3:1;
	unsigned int rsv2:1;
	unsigned int rsv1:1;
	unsigned int fin:1;
	
	unsigned int payloadLen:7;
	unsigned int mask:1;
	
	
	union {
		struct {
			UInt8 maskingKey[4];
			UInt8 data[0];
		} mpayload125;
		
		struct { 
			UInt16 len; // length stored here if (payloadLen == 126)
			UInt8 maskingKey[4];
			UInt8 data[0];
		} mpayload126;
		
		struct { 
			UInt64 len; // length stored here if (payloadLen == 127)
			UInt8 maskingKey[4];
			UInt8 data[0];
		} mpayload127;
		
		struct {
			UInt8 data[0];
		} upayload125;
		
		struct { 
			UInt16 len; // length stored here if (payloadLen == 126)
			UInt8 data[0];
		} upayload126;
		
		struct { 
			UInt64 len; // length stored here if (payloadLen == 127)
			UInt8 data[0];
		} upayload127;
	};
	
	
} FrameHeader_HYBI_07;
#pragma options align=reset


#pragma mark Write

// Internal function, write provided buffer in a frame [0x00 ... 0xff]
static CFIndex __WebSocketClientWriteFrame_HYBI_06(WebSocketClientRef client, CFDataRef value) {
	
	UInt8 *buffer = (UInt8 *)CFDataGetBytePtr(value);
	CFIndex length = CFDataGetLength(value);
	
	CFIndex bytes = -1;
	if (CFWriteStreamCanAcceptBytes(client->write)) {
		CFWriteStreamWrite(client->write, (UInt8[]){ 0x00 }, 1);
		bytes = CFWriteStreamWrite(client->write, buffer, length);
		CFWriteStreamWrite(client->write, (UInt8[]){ 0xff }, 1);
	} else {
		client->alive = false;
		printf("[CWS] __WebSocketClientWriteFrame: can't write to stream\n");
	}

	return bytes;
}


static CFIndex __WebSocketClientWriteFrame_HYBI_07(WebSocketClientRef client, CFDataRef value) 
{
	CFIndex payloadLen = CFDataGetLength(value);
	CFIndex bufferLen = sizeof(FrameHeader_HYBI_07) + payloadLen;
	UInt8 *buffer = malloc(bufferLen);
	if (!buffer) {
		printf("[CWS] Failed to allocate bufferr\r");
		return -1;
	}
	
	memset(buffer, 0, bufferLen);
	FrameHeader_HYBI_07 *frame = (FrameHeader_HYBI_07 *)buffer;
	
	UInt8 *payload = NULL;
	UInt8 maskingKey[4];
	
#if (TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR) 
	int error = SecRandomCopyBytes(kSecRandomDefault, sizeof(maskingKey), maskingKey);
	if (error != 0) {
		printf("[CWS] Failed to generate random number\r");
		return -1;
	}
#else
	int urandom = open("/dev/urandom", O_RDONLY);
	if (urandom < 0) {
		printf("[CWS] Failed to generate random number\r");
		return -1;
	}
	
	read(urandom, &maskingKey, sizeof(maskingKey));
	close(urandom);
#endif


	frame->fin = 0x1;
	frame->opcode = 0x1;
	frame->mask = 0x1;

	CFIndex headerLen = 0;

	if (payloadLen < 126) {
		headerLen = 2 + 4;
		frame->payloadLen = payloadLen;
		memcpy(frame->mpayload125.maskingKey, maskingKey, sizeof(maskingKey));
		payload = frame->mpayload125.data;
	}
	else if (payloadLen <= 0xFFFF) {
		headerLen = 2 + 2 + 4;
		frame->payloadLen = 126;
		frame->mpayload126.len = EndianU16_NtoB(payloadLen);
		memcpy(frame->mpayload126.maskingKey, maskingKey, sizeof(maskingKey));
		payload = frame->mpayload126.data;
	}
	else {
		headerLen = 2 + 8 + 4;
		frame->payloadLen = 127;
		frame->mpayload127.len = EndianU64_NtoB(payloadLen);
		memcpy(frame->mpayload127.maskingKey, maskingKey, sizeof(maskingKey));
		payload = frame->mpayload127.data;
	}

	
	int maskIndex = 0;
	UInt8 *p = payload;
	UInt8 *d = (UInt8 *)CFDataGetBytePtr(value);

	for (int i = 0; i < payloadLen; ++i) {
		*p++ = *d++ ^ maskingKey[maskIndex];
		maskIndex = (maskIndex + 1) % 4;
	}

	CFIndex bytes = -1;
	if (CFWriteStreamCanAcceptBytes(client->write)) {
		bytes = CFWriteStreamWrite(client->write, buffer, headerLen + payloadLen);
	} else {
		client->alive = false;
		printf("[CWS] __WebSocketClientWriteFrame_HYBI_07: can't write to stream\r");
	}
	
	
	free(buffer);
	
	return bytes;
}

CFIndex WebSocketClientWriteWithData(WebSocketClientRef client, CFDataRef value) {
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] >WebSocketClientWriteWithData\r");

	if (!client || !client->write || !client->alive) return -1;
	if (!value || CFDataGetLength(value) == 0) return -1;
	
	CFIndex result = -1;
	if (client->protocol == kWebSocketProtocolDraftIETF_HYBI_07) {
		result = __WebSocketClientWriteFrame_HYBI_07(client, value);
	}
	else {
		result = __WebSocketClientWriteFrame_HYBI_06(client, value);
	}
	
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] <WebSocketClientWriteWithData: %jd\r", (intmax_t)result);
	
	return result;
}

CFIndex WebSocketClientWriteWithString(WebSocketClientRef client, CFStringRef value) {
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] >WebSocketClientWriteWithString\r");
	
	CFIndex bytes = -1;
	if (!client) return bytes;
	if (!value) return bytes;
	
	CFDataRef data = CFStringCreateExternalRepresentation(client->allocator, value, kCFStringEncodingUTF8, 0);
	if (data) {
		bytes = WebSocketClientWriteWithData(client, data);
		CFRelease(data);
	}
	
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] <WebSocketClientWriteWithString: %jd\r", (intmax_t)bytes);
	
	return bytes;
}

#pragma mark Read callback

bool __WebSocketClientWriteHandShake(WebSocketClientRef client);

static void __WebSocketClientRead_HYBI_06(WebSocketClientRef client, CFReadStreamRef stream) {
	UInt8 b[4096];
	memset(b, 0, sizeof(b));
	CFIndex by = 0;
	
	by = CFReadStreamRead(stream, b, sizeof(b) - 1);
	if (by > 2) {
		const char *from = (const char *)b + 1;
		const char *to = strchr(from, 0xff);
		while (to) {
			if (client->webSocket->callbacks.didClientReadCallback) {
				CFDataRef data = CFDataCreate(client->allocator, (const void *)from, to - from);
				if (data) {
					CFStringRef string = CFStringCreateWithBytes(client->allocator, CFDataGetBytePtr(data), CFDataGetLength(data), kCFStringEncodingUTF8, 0);
					if (string) {
						client->webSocket->callbacks.didClientReadCallback(client->webSocket, client, string);
						CFRelease(string);
					}
					CFRelease(data);
				}
			}
			from = to + 2;
			to = strchr(from, 0xff);
		}
	}
	char *end = strchr((const char *)b, 0xff);
	if (end) {
		*end = 0x00;
	}
}	


static void __WebSocketClientRead_HYBI_07(WebSocketClientRef client, CFReadStreamRef stream) {
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] >__WebSocketClientRead_HYBI_07\n");

	UInt8 b[4096];
	memset(b, 0, sizeof(b));
	CFIndex by = 0;
	
	by = CFReadStreamRead(stream, b, sizeof(b) - 1);
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] bytes: %jd\r", (intmax_t)by);
	if (by < 2) {
		WebSocketClientDisconnect(client);
		return;
	}
	
	FrameHeader_HYBI_07 *header = (FrameHeader_HYBI_07 *)b;
	if (DEBUG_WEBSOCKETCLIENT) {
		printf("Fin: %s\r", header->fin ? "yes" : "no");
		printf("Opcode: %jd\r", (intmax_t)header->opcode);
		printf("Masked: %s\r", header->mask ? "yes" : "no");
		printf("Length: %jd\r", (intmax_t)header->payloadLen);
	}
	
	UInt8 *payload = NULL;
	CFIndex payloadLen = 0;
	UInt8 *maskingKey;
	if (header->mask) {
		if (header->payloadLen < 126) {
			payloadLen = header->payloadLen;
			payload = header->mpayload125.data;
			maskingKey = header->mpayload125.maskingKey;
		}
		else if (header->payloadLen == 126) {
			payloadLen = EndianU16_BtoN(header->mpayload126.len);
			payload = header->mpayload126.data;
			maskingKey = header->mpayload126.maskingKey;
		}
		else {
			payloadLen = EndianU64_BtoN(header->mpayload127.len);
			payload = header->mpayload127.data;
			maskingKey = header->mpayload127.maskingKey;
		}
	}
	else {
		if (header->payloadLen < 126) {
			payloadLen = header->payloadLen;
			payload = header->upayload125.data;
		}
		else if (header->payloadLen == 126) {
			payloadLen = EndianU16_BtoN(header->upayload126.len);
			payload = header->upayload126.data;
		}
		else {
			payloadLen = EndianU64_BtoN(header->upayload127.len);
			payload = header->upayload127.data;
		}
	}
	
	if (header->opcode == 0x8) {
		printf("[CWS] Closing");
		return;
	}

	if (header->opcode == 0x9) {
		printf("[CWS] Ping");
		return;
	}

	if (header->opcode == 0xA) {
		printf("[CWS] Pong");
		return;
	}

	printf("[CWS] Payload Length: %jd", (intmax_t)payloadLen);

	if (payloadLen >= by) {
		printf("[CWS] Invalid payload length: %jd", (intmax_t)payloadLen);
		return;
	}
	
	if (header->mask) {
		UInt8 *p = payload;
		int maskIndex = 0;
		for (int i = 0; i < payloadLen; ++i) {
			*p = *p ^ maskingKey[maskIndex];
			p += 1;
			maskIndex = (maskIndex + 1) % 4;
		}
	}

	
	if (payload) {
		if (client->webSocket->callbacks.didClientReadCallback) {
			CFDataRef data = CFDataCreate(client->allocator, (const void *)payload, payloadLen);
			if (!data) {
				printf("[CWS] Data error");
			}
			else {
				CFStringRef string = CFStringCreateWithBytes(client->allocator, CFDataGetBytePtr(data), CFDataGetLength(data), kCFStringEncodingUTF8, 0);
				if (string) {
					if (DEBUG_WEBSOCKETCLIENT) CFShowStr(string);

					client->webSocket->callbacks.didClientReadCallback(client->webSocket, client, string);
					CFRelease(string);
				}
				CFRelease(data);
			}
		}
	}
	
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] <__WebSocketClientRead_HYBI_07\n");
}	


static void __WebSocketPerformHandshake(WebSocketClientRef client) {
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] >__WebSocketPerformHandshake\n");
	
	if (!__WebSocketClientReadHandShake(client)) {
		printf("[CWS] TODO: Didn't read handshake and __WebSocketClientReadHandShake failed.\r");
		return;
	}
	
	if (client->didWriteHandShake) {
		printf("[CWS] TODO: Just read handshake and handshake already written, shouldn't happen, fault?\r");
		return;
	}
	
	if (!client->write) {
		printf("[CWS] Error: no write stream\r");
	}
	
	if (!CFWriteStreamCanAcceptBytes(client->write)) {
		if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] TODO: Didn't handshake and client doesn't accept bytes yet. Write callback will handle writting handshake as soon as we can write.\r");
		return;
	}	
	
	if (__WebSocketClientWriteHandShake(client)) {
		if (DEBUG_WEBSOCKETCLIENT) printf("Successfully written handshake\n");
		__WebSocketAppendClient(client->webSocket, client);
	}
	else {
		printf("[CWS] Error writting handshake\n");
	}
	
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] <__WebSocketPerformHandshake\n");
}

static void __WebSocketClientRead(WebSocketClientRef client, CFReadStreamRef stream) {
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] >__WebSocketClientRead\r");
	
	if (!CFReadStreamHasBytesAvailable(client->read)) {
		printf("[CWS] Failed to read, no bytes available\r");
		return;	
	}
	
	if (client->protocol == kWebSocketProtocolDraftIETF_HYBI_06 || client->protocol == kWebSocketProtocolDraftIETF_HYBI_00) {
		__WebSocketClientRead_HYBI_06(client, stream);
	}
	else if (client->protocol == kWebSocketProtocolDraftIETF_HYBI_07) {
		__WebSocketClientRead_HYBI_07(client, stream);
	}
	else {
		printf("[CWS] Failed to read, protocol not supported: %jd", (intmax_t)client->protocol);
	}
	
	if (!client->didWriteHandShake && CFWriteStreamCanAcceptBytes(client->write)) {
		__WebSocketPerformHandshake(client);
		return;
	}	
	
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] <__WebSocketClientRead\r");
}


static void __WebSocketClientReadCallBack(CFReadStreamRef stream, CFStreamEventType eventType, void *info) {
	WebSocketClientRef client = info;
	if (!client) return;

	switch (eventType) {
		case kCFStreamEventOpenCompleted:
			if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] kCFStreamEventOpenCompleted\r");
			break;
			
		case kCFStreamEventHasBytesAvailable:
			if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] kCFStreamEventHasBytesAvailable\r");
			if (client->didReadHandShake && client->didWriteHandShake) {
				// Did handshake already and there are bytes to read.
				// It's incomming message.
				__WebSocketClientRead(client, stream);
			}
			else {
				__WebSocketPerformHandshake(client);
			}

			break;
			
		case kCFStreamEventErrorOccurred:
			if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] kCFStreamEventErrorOccurred\r");
			break;
			
		case kCFStreamEventEndEncountered:
			if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] kCFStreamEventEndEncountered\r");
			break;
			
		default:
			printf("[CWS] Unknown event type");
			break;
	}
}

bool __WebSocketClientWriteWithHTTPMessage(WebSocketClientRef client, CFHTTPMessageRef message) {
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] Writing HTTP message: ");
	
	bool success = 0;
	if (client && message) {
		CFDataRef data = CFHTTPMessageCopySerializedMessage(message);
		if (data) {
			CFIndex written = CFWriteStreamWrite(client->write, CFDataGetBytePtr(data), CFDataGetLength(data));
			if (written == CFDataGetLength(data)) {
				success = 1; // TODO: do it properly
			}
			client->didWriteHandShake = 1;
			CFRelease(data);
		}
	}
	
	if (DEBUG_WEBSOCKETCLIENT) printf(success ? "Success\r" : "Failed\r");

	return success;
}

static bool __WebSocketClientWriteHandShakeDraftIETF_HYBI_00(WebSocketClientRef client) {
	bool success = 0;
	if (client) {
		if (client->protocol == kWebSocketProtocolDraftIETF_HYBI_00) {
			CFStringRef key1 = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-Websocket-Key1"));
			CFStringRef key2 = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-Websocket-Key2"));
			CFDataRef key3 = CFHTTPMessageCopyBody(client->handShakeRequestHTTPMessage);
			CFStringRef origin = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Origin"));
			CFStringRef host = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Host"));
			
			if (client->origin) CFRelease(client->origin);
			client->origin = CFRetain(origin);
			
			CFHTTPMessageRef response = CFHTTPMessageCreateEmpty(NULL, 0);
			CFHTTPMessageAppendBytes(response, (const UInt8 *)"HTTP/1.1 101 Web Socket Protocol Handshake\r\n", 44);
			CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Upgrade"), CFSTR("WebSocket"));
			CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Connection"), CFSTR("Upgrade"));
			CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Sec-Websocket-Origin"), origin);
			
			CFMutableStringRef location = CFStringCreateMutable(client->allocator, 0);
			CFStringAppend(location, CFSTR("ws://"));
			CFStringAppend(location, host);
			CFStringAppend(location, CFSTR("/"));
			CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Sec-Websocket-Location"), location);
			CFRelease(location);
			
			// Set MD5 hash
			{
				CFMutableDataRef mutable = CFDataCreateMutable(client->allocator, 0);
				__WebSocketDataAppendMagickNumberWithKeyValueString(mutable, key1);
				__WebSocketDataAppendMagickNumberWithKeyValueString(mutable, key2);
				CFDataAppendBytes(mutable, CFDataGetBytePtr(key3), CFDataGetLength(key3));
				CFDataRef data = __WebSocketCreateMD5Data(client->allocator, mutable);
				CFHTTPMessageSetBody(response, data);
				CFRelease(mutable);
				CFRelease(data);
			}
			
			// CFShow(response);
			
			success = __WebSocketClientWriteWithHTTPMessage(client, response);
			
			CFRelease(response);
			
			CFRelease(host);
			CFRelease(origin);
			CFRelease(key3);
			CFRelease(key2);
			CFRelease(key1);
		}
	}
	return success;
}

// The source code has been copied and modified from
// http://www.opensource.apple.com/source/CFNetwork/CFNetwork-128/HTTP/CFHTTPAuthentication.c
// See _CFEncodeBase64 function. The source code has been released under
// Apple Public Source License Version 2.0 http://www.opensource.apple.com/apsl/
static CFStringRef __WebSocketCreateBase64StringWithData(CFAllocatorRef allocator, CFDataRef inputData) {
	unsigned outDataLen;	
	CFStringRef result = NULL;
	unsigned char *outData = cuEnc64(CFDataGetBytePtr(inputData), (unsigned int)CFDataGetLength(inputData), &outDataLen);
	if(outData) {
		// current cuEnc64 appends \n and NULL, trim them
		unsigned char *c = outData + outDataLen - 1;
		while((*c == '\n') || (*c == '\0')) {
			c--;
			outDataLen--;
		}
		result = CFStringCreateWithBytes(allocator, outData, outDataLen, kCFStringEncodingASCII, FALSE);
		free(outData);
	}
	return result;
}

static bool __WebSocketClientWriteHandShakeDraftIETF_HYBI_06(WebSocketClientRef client) {
	if (!client) return false;

	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] WebSocketClientWriteHandShakeDraftIETF_HYBI_06\n");

	CFStringRef key = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-WebSocket-Key"));
	CFStringRef keyWithMagick = CFStringCreateWithFormat(client->allocator, NULL, CFSTR("%@%@"), key, CFSTR("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
	CFDataRef keyWithMagickSHA1 = __WebSocketCreateSHA1DataWithString(client->allocator, keyWithMagick, kCFStringEncodingUTF8);
	CFStringRef keyWithMagickSHA1Base64 = __WebSocketCreateBase64StringWithData(client->allocator, keyWithMagickSHA1);
	
	// CFShow(keyWithMagickSHA1Base64);
	
	CFStringRef origin = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-WebSocket-Origin"));
	CFStringRef host = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Host"));
	
	if (client->origin) CFRelease(client->origin);
	client->origin = CFRetain(origin);
	
	CFHTTPMessageRef response = CFHTTPMessageCreateEmpty(NULL, 0);
	CFHTTPMessageAppendBytes(response, (const UInt8 *)"HTTP/1.1 101 Switching Protocols\r\n", 44);
	CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Upgrade"), CFSTR("websocket"));
	CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Connection"), CFSTR("Upgrade"));
	CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Sec-WebSocket-Accept"), keyWithMagickSHA1Base64);
	
	bool success = __WebSocketClientWriteWithHTTPMessage(client, response);
	
	CFRelease(response);
	
	CFRelease(keyWithMagickSHA1Base64);
	CFRelease(keyWithMagickSHA1);
	CFRelease(keyWithMagick);
	CFRelease(key);
	CFRelease(origin);
	CFRelease(host);

	return success;
}

static bool __WebSocketClientWriteHandShakeDraftIETF_HYBI_07(WebSocketClientRef client) {
	if (!client) return false;
	
	if (DEBUG_WEBSOCKETCLIENT) printf("[CWS] WebSocketClientWriteHandShakeDraftIETF_HYBI_07\n");
	
	CFStringRef key = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-WebSocket-Key"));
	CFStringRef keyWithMagick = CFStringCreateWithFormat(client->allocator, NULL, CFSTR("%@%@"), key, CFSTR("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
	CFDataRef keyWithMagickSHA1 = __WebSocketCreateSHA1DataWithString(client->allocator, keyWithMagick, kCFStringEncodingUTF8);
	CFStringRef keyWithMagickSHA1Base64 = __WebSocketCreateBase64StringWithData(client->allocator, keyWithMagickSHA1);
	
	// CFShow(keyWithMagickSHA1Base64);
	
	CFStringRef origin = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-WebSocket-Origin"));
	CFStringRef host = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Host"));
	
	if (client->origin) CFRelease(client->origin);
	client->origin = CFRetain(origin);
	
	CFHTTPMessageRef response = CFHTTPMessageCreateEmpty(NULL, 0);
	CFHTTPMessageAppendBytes(response, (const UInt8 *)"HTTP/1.1 101 Switching Protocols\r\n", 44);
	CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Upgrade"), CFSTR("websocket"));
	CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Connection"), CFSTR("Upgrade"));
	CFHTTPMessageSetHeaderFieldValue(response, CFSTR("Sec-WebSocket-Accept"), keyWithMagickSHA1Base64);
	
	bool success = __WebSocketClientWriteWithHTTPMessage(client, response);
	
	CFRelease(response);
	
	CFRelease(keyWithMagickSHA1Base64);
	CFRelease(keyWithMagickSHA1);
	CFRelease(keyWithMagick);
	CFRelease(key);
	CFRelease(origin);
	CFRelease(host);
	
	return success;
}


bool __WebSocketClientWriteHandShake(WebSocketClientRef client) {
	bool success = 0;
	if (client->didReadHandShake) {
		if (!client->didWriteHandShake) {
			switch (client->protocol) {
				case kWebSocketProtocolDraftIETF_HYBI_00:
					success = __WebSocketClientWriteHandShakeDraftIETF_HYBI_00(client);
					break;
				case kWebSocketProtocolDraftIETF_HYBI_06:
					success = __WebSocketClientWriteHandShakeDraftIETF_HYBI_06(client);
					break;
				case kWebSocketProtocolDraftIETF_HYBI_07:
					success = __WebSocketClientWriteHandShakeDraftIETF_HYBI_07(client);
					break;
				default:
					printf("Unsupported protocol, can't write handshake. TODO: disconnect\n");
					// Unknown protocol, can't write handshake
					break;
			}
		}
	}
	return success;
}

static void __WebSocketClientWriteCallBack(CFWriteStreamRef stream, CFStreamEventType eventType, void *info) {
	WebSocketClientRef client = info;
	if (client) {
		switch (eventType) {
				
			case kCFStreamEventCanAcceptBytes:
				if (!client->didWriteHandShake && client->didReadHandShake)
					__WebSocketClientWriteHandShake(client);
				break;
				
			case kCFStreamEventEndEncountered:
				break;
				
			case kCFStreamEventErrorOccurred:
				client->alive = false;
				printf("kCFStreamEventErrorOccurred (write)\n");
				CFErrorRef error = CFWriteStreamCopyError(stream);
				if (error) {
					CFShow(error);
					CFRelease(error);
				}
				break;
				
			default:
				break;
		}
	}
}

#pragma mark Lifecycle

WebSocketClientRef WebSocketClientCreate(WebSocketRef webSocket, CFSocketNativeHandle handle) {
	WebSocketClientRef client = NULL;
	if (webSocket) {
		client = CFAllocatorAllocate(webSocket->allocator, sizeof(WebSocketClient), 0);
		if (client) {
			client->allocator = webSocket->allocator ? CFRetain(webSocket->allocator) : NULL;
			client->retainCount = 1;
			
			CFUUIDRef uuidRef = CFUUIDCreate(webSocket->allocator);
			client->uuid = CFUUIDCreateString(webSocket->allocator, uuidRef);
			CFRelease(uuidRef);
			
			client->origin = NULL;
			client->alive = true;
			
			client->webSocket = WebSocketRetain(webSocket);
			client->handle = handle;
			
			client->read = NULL;
			client->write = NULL;
			
			client->context.version = 0;
			client->context.info = client;
			client->context.copyDescription = NULL;
			client->context.retain = NULL;
			client->context.release = NULL;
			
			client->handShakeRequestHTTPMessage = NULL;
			client->didReadHandShake = 0;
			client->didWriteHandShake = 0;
			client->protocol = kWebSocketProtocolUnknown;
			
			CFStreamCreatePairWithSocket(client->allocator, handle, &client->read, &client->write);
			if (!client->read || !client->write) {
				close(handle);
				fprintf(stderr, "CFStreamCreatePairWithSocket() failed, %p, %p\n", read, write);
			} else {
				//        printf("ok\n");
			}
			
			CFReadStreamSetClient(client->read, kCFStreamEventOpenCompleted | kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered, __WebSocketClientReadCallBack, &client->context);
			CFWriteStreamSetClient(client->write, kCFStreamEventOpenCompleted | kCFStreamEventCanAcceptBytes | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered, __WebSocketClientWriteCallBack, &client->context);
			
			CFReadStreamScheduleWithRunLoop(client->read, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
			CFWriteStreamScheduleWithRunLoop(client->write, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
			
			if (!CFReadStreamOpen(client->read)) {
				printf("couldn't open read stream\n");
			} else {
				//        printf("opened read stream\n");
			}
			
			if (!CFWriteStreamOpen(client->write)) {
				printf("couldn't open write stream\n");
			} else {
				//        printf("opened write stream\n");
			}
		}
	}
	return client;
}

WebSocketClientRef WebSocketClientRetain(WebSocketClientRef client) {
	if (client)
		client->retainCount++;
	return client;
}

WebSocketClientRef WebSocketClientRelease(WebSocketClientRef client) {
	if (!client) return NULL;
	
	if (--client->retainCount == 0) {
		CFAllocatorRef allocator = client->allocator;
		
		WebSocketClientDisconnect(client);
		
		if (client->uuid) {
			CFRelease(client->uuid);
			client->uuid = NULL;
		}
		
		if (client->origin) {
			CFRelease(client->origin);
			client->origin = NULL;
		}
		
		CFAllocatorDeallocate(allocator, client);
		client = NULL;
		
		if (allocator)
			CFRelease(allocator);
	}
	
	return client;
}

void WebSocketClientDisconnect(WebSocketClientRef client) {
	if (!client) return;
	
	if (client->read) {
		if (CFReadStreamGetStatus(client->read) != kCFStreamStatusClosed)
			CFReadStreamClose(client->read);
		CFRelease(client->read);
		client->read = NULL;
	}
	
	if (client->write) {
		if (CFWriteStreamGetStatus(client->write) != kCFStreamStatusClosed)
			CFWriteStreamClose(client->write);
		CFRelease(client->write);
		client->write = NULL;
	}
}



#pragma Handshake

// Return magic number for the key needed to generate handshake hash
uint32_t __WebSocketGetMagicNumberWithKeyValueString(CFStringRef string) {
	uint32_t magick = -1;
	if (string) {
		UInt8 buffer[__WebSocketMaxHeaderKeyLength];
		CFIndex usedBufferLength = 0;
		char numberBuffer[__WebSocketMaxHeaderKeyLength];
		memset(numberBuffer, 0, sizeof(numberBuffer));
		CFIndex usedNumberBufferLength = 0;
		CFStringGetBytes(string, CFRangeMake(0, CFStringGetLength(string)), kCFStringEncodingASCII, 0, 0, buffer, sizeof(buffer), &usedBufferLength);
		UInt32 number = 0;
		UInt32 spaces = 0;
		for (int i = 0; i < usedBufferLength; i++) {
			if (buffer[i] >= '0' && buffer[i] <= '9')
				numberBuffer[usedNumberBufferLength++] = buffer[i];
			if (buffer[i] == ' ')
				spaces++;
		}
		if (spaces > 0) {
			number = (UInt32)strtoul(numberBuffer, NULL, 10);
			magick = number / spaces;
		}
	}
	return magick;
}

// Appends big-endian uint32 magic number with key string to the mutable data
bool __WebSocketDataAppendMagickNumberWithKeyValueString(CFMutableDataRef data, CFStringRef string) {
	bool success = 0;
	if (data && string) {
		uint32_t magick = __WebSocketGetMagicNumberWithKeyValueString(string);
		uint32_t swapped = CFSwapInt32HostToBig(magick);
		CFDataAppendBytes(data, (const void *)&swapped, sizeof(swapped));
		success = 1;
	}
	return success;
}

CFDataRef __WebSocketCreateMD5Data(CFAllocatorRef allocator, CFDataRef value) {
	unsigned char digest[CC_MD5_DIGEST_LENGTH];
	CC_MD5((unsigned char *)CFDataGetBytePtr(value), (CC_LONG)CFDataGetLength(value), digest);
	return CFDataCreate(allocator, digest, CC_MD5_DIGEST_LENGTH);
}

CFDataRef __WebSocketCreateSHA1DataWithData(CFAllocatorRef allocator, CFDataRef value) {
	unsigned char digest[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1((unsigned char *)CFDataGetBytePtr(value), (CC_LONG)CFDataGetLength(value), digest);
	return CFDataCreate(allocator, digest, CC_SHA1_DIGEST_LENGTH);
}

CFDataRef __WebSocketCreateSHA1DataWithString(CFAllocatorRef allocator, CFStringRef value, CFStringEncoding encoding) {
	CFDataRef data = NULL;
	if (value) {
		CFDataRef valueData = CFStringCreateExternalRepresentation(allocator, value, encoding, 0);
		if (valueData) {
			data = __WebSocketCreateSHA1DataWithData(allocator, valueData);
			CFRelease(valueData);
		}
	}
	return data;
}

static bool __WebSocketClientHandShakeConsumeHTTPMessage(WebSocketClientRef client) {
	bool success = 0;
	if (client) {
		UInt8 buffer[4096];
		CFIndex bytes = 0;
		client->handShakeRequestHTTPMessage = CFHTTPMessageCreateEmpty(client->allocator, 1);
		while (CFReadStreamHasBytesAvailable(client->read)) {
			if ((bytes = CFReadStreamRead(client->read, buffer, sizeof(buffer))) > 0) {
				CFHTTPMessageAppendBytes(client->handShakeRequestHTTPMessage, buffer, bytes);
			} else if (bytes < 0) {
				CFErrorRef error = CFReadStreamCopyError(client->read);
				CFShow(error);
				CFRelease(error);
				goto fin;
			}
		}
		success = 1;
	}
fin:
	return success;
}

static bool __WebSocketClientHandShakeUpdateProtocolBasedOnHTTPMessage(WebSocketClientRef client) {
	if (!client) return false;

	client->protocol = kWebSocketProtocolUnknown;
	CFStringRef upgrade = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Upgrade"));
	if (!upgrade) {
		printf("[CWS] Upgrade field is missing");
		return false;
	}
	
	bool isWebSocket = (CFStringCompare(CFSTR("WebSocket"), upgrade, kCFCompareCaseInsensitive) == kCFCompareEqualTo);
	CFRelease(upgrade);

	if (!isWebSocket) {
		printf("[CWS] Error: invalid Upgrade HTTP field, expected WebSocket");
		return false;
	}
	
	bool success = false;
	CFStringRef version = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-WebSocket-Version"));
	if (version) {
		if (CFStringCompare(CFSTR("6"), version, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
			printf("[CWS] Protocol: HYBI_06\n");
			client->protocol = kWebSocketProtocolDraftIETF_HYBI_06;
			success = true;
		} 
		else if (CFStringCompare(CFSTR("7"), version, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
			printf("[CWS] Protocol: HYBI_07\n");
			client->protocol = kWebSocketProtocolDraftIETF_HYBI_07;
			success = true;
		} 
		else if (CFStringCompare(CFSTR("10"), version, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
			printf("[CWS] Protocol: HYBI_10\n");
			client->protocol = kWebSocketProtocolDraftIETF_HYBI_10;
			success = true;
		} 
		else { // Version different than 6, we don't know of any other, leave the protocol as unknown
			printf("Unsupported protocol version: ");
			CFShowStr(version);
		}
		CFRelease(version);
	} 
	else {
		// Sec-WebSocket-Version header field is missing.
		// It may be 00 protocol, which doesn't have this field.
		// 00 protocol has to have Sec-WebSocket-Key1 and Sec-WebSocket-Key2
		// fields - let's check for those.
		CFStringRef key1 = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-WebSocket-Key1"));
		CFStringRef key2 = CFHTTPMessageCopyHeaderFieldValue(client->handShakeRequestHTTPMessage, CFSTR("Sec-WebSocket-Key2"));
		if (key1 && key2) {
			client->protocol = kWebSocketProtocolDraftIETF_HYBI_00;
			success = true;
		}
		else { // Key2 missing, no version specified = unknown protocol
			printf("[CWS] Unknown protocol.");
		}
		
		if (key1) CFRelease(key1);
		if (key2) CFRelease(key2);
	}

	return success;
}

bool __WebSocketClientReadHandShake(WebSocketClientRef client) {
	if (!client) return false;
	
	bool success = __WebSocketClientHandShakeConsumeHTTPMessage(client);
	if (success) success = __WebSocketClientHandShakeUpdateProtocolBasedOnHTTPMessage(client);
	
	if (!success) {
		printf("[CWS] Failed to read handshake\r");
		return false;
	}

	client->didReadHandShake = 1;
	if (DEBUG_WEBSOCKETCLIENT) {
		// Dump http message
		CFDictionaryRef headerFields = CFHTTPMessageCopyAllHeaderFields(client->handShakeRequestHTTPMessage);
		if (headerFields) {
			CFShow(headerFields);
			CFRelease(headerFields);
		}
	}

	return true;
}

