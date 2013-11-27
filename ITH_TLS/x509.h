/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ITH_X509
#define ITH_X509

//Main purpose: to extract public modulus from certificate.
//Do not verify certificate. So man-in-the-middle attack will success.

class ASN1Object
{
public:
	ASN1Object() : type(0), len(0) {}
	unsigned char* Parse(unsigned char* in);
	unsigned char ASN1Tag()
	{
		return type & 0x1F;
	}
	bool IsConstructed()
	{
		return (type & 0x20) > 0;
	}
	unsigned char ASN1Class()
	{
		return type >> 6;
	}
	unsigned int ASN1Len()
	{
		return len;
	}
protected:
	unsigned int type, len;
	//type = {
	//  Class : 2,
	//  P/C : 1,
	//  Tag : 5
};
class ASN1Sequence : public ASN1Object
{
public:
	unsigned char* Parse(unsigned char* in);
protected:

};
class ASN1SetItem : public ASN1Object
{
public:
	virtual ~ASN1SetItem();
	unsigned char* Parse(unsigned char* in);
	void SetNext(ASN1SetItem* s) {next = s;}
protected:
	ASN1SetItem* next;
};
class ASN1Interger : public ASN1Object
{
public:
	ASN1Interger()
	{
		value_long = 0;
	}
	~ASN1Interger();
	unsigned char* Parse(unsigned char* in);
	unsigned char* Value();
protected:
	union
	{
		unsigned char* value_long;
		unsigned char value_short[4];
	};
	
};
class ASN1Bitstring : public ASN1Object
{
public:
	unsigned char* Parse(unsigned char* in);
};
class ASN1ObjectIdentifier : public ASN1Object
{
public:
	ASN1ObjectIdentifier()
	{
		oid_long = 0;
	}
	virtual ~ASN1ObjectIdentifier();
	unsigned char* Parse(unsigned char* in);
	unsigned char PKCS1Algorithm();
	unsigned char RDNType();
protected:
	union
	{
		unsigned char* oid_long;
		unsigned char oid_short[4];
	};

};
class ASN1CharacterString : public ASN1Object
{
public:
	ASN1CharacterString() {str_long = 0;}
	~ASN1CharacterString();
	unsigned char* Parse(unsigned char* in);
protected:
	union
	{
		unsigned char str_short[4];
		unsigned char *str_long;
	};
};
class CertificateVersion : ASN1Object
{
public:
	CertificateVersion(int version = 0) : ver(version) {}
	unsigned char* Parse(unsigned char* in);
	unsigned char Version(){return ver;}
protected:
	unsigned char ver;
};
/*
AlgorithmIdentifier{ALGORITHM:SupportedAlgorithms} ::= SEQUENCE {
	algorithm ALGORITHM.&id ({SupportedAlgorithms}),
	parameters ALGORITHM.&Type ({SupportedAlgorithms}{ @algorithm}) OPTIONAL 
}
*/
class AlgorithmIdentifier : public ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
protected:
	ASN1ObjectIdentifier algorithm;
	ASN1Object param; //null = 0x5 0x0
};
class RDNSequenceItem : public ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
protected:
	ASN1ObjectIdentifier item;
	ASN1CharacterString str;
};
class RDNSequence : public ASN1SetItem
{
public:
	RDNSequence() {next = 0;}
	void SetNext(RDNSequence* n) {next = n;}
	unsigned char* Parse(unsigned char* in);
protected:
	RDNSequenceItem item;
};
class Name : public ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
protected:
	RDNSequence head;
};
class UTCTime : ASN1Object
{
public:
	unsigned char* Parse(unsigned char* in);
protected:
	char utcStr[0x10]; //12 used.
};
class Validity : ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
protected:
	UTCTime notBefore;
	UTCTime notAfter;
};
class RSAKeyItem : public ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
	unsigned int PublicKey(unsigned char* k);
protected:
	ASN1Interger public_mod;
	ASN1Interger public_exp;
};
class RSAKeyInfo : public ASN1Bitstring
{
public:
	unsigned char* Parse(unsigned char* in);
	unsigned int PublicKey(unsigned char* k);
protected:
	RSAKeyItem key;
};
class SubjectPublicKeyInfo : public ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
	unsigned int PublicKey(unsigned char* k);
protected:
	AlgorithmIdentifier algorithm;
	RSAKeyInfo key;
};
/* version 1.
CertificateContent ::= SEQUENCE {
	version [0] Version DEFAULT v1,
	serialNumber CertificateSerialNumber,
	signature AlgorithmIdentifier{{SupportedAlgorithms}},
	issuer Name,
	validity Validity,
	subject Name,
	subjectPublicKeyInfo SubjectPublicKeyInfo,
}
*/
class CertificateContent : public ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
	unsigned int PublicKey(unsigned char* k);
protected:
	typedef ASN1Interger CertificateSerialNumber;
	CertificateVersion version;
	CertificateSerialNumber serial;
	AlgorithmIdentifier signature;
	Name issuer;
	Validity validity;
	Name subject;
	SubjectPublicKeyInfo subjectPublicKeyInfo;
};
class SignatureBitstring : public ASN1Bitstring
{
public:
	virtual ~SignatureBitstring();
	unsigned char* Parse(unsigned char* in);
protected:
	unsigned char* value;
};
class CertificateSignature : public AlgorithmIdentifier
{
public:
	unsigned char* Parse(unsigned char* in);
protected:
	SignatureBitstring signature;
};
//Certificate ::= SIGNED { CertificateContent }
class Certificate : public ASN1Sequence
{
public:
	unsigned char* Parse(unsigned char* in);
	unsigned int PublicKey(unsigned char* k);
protected:
	CertificateContent certificate;
	CertificateSignature signature;
};
#endif