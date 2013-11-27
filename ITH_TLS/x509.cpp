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

#include "x509.h"

#include <memory.h>
#include <intrin.h>

#include <ITH\mem.h>

ASN1SetItem::~ASN1SetItem() 
{
	if (next)
	{
		delete next;
		next = 0;
	}
}
ASN1Interger::~ASN1Interger()
{
	if (value_long && len > 4)
	{
		delete value_long;			
	}
	value_long = 0;
}
ASN1ObjectIdentifier::~ASN1ObjectIdentifier()
{
	if (len > 4)
	{
		delete oid_long;
	}
	oid_long = 0;
}
ASN1CharacterString::~ASN1CharacterString() 
{
	if (len > 4)
		delete str_long;
	str_long = 0;
}
SignatureBitstring::~SignatureBitstring() 
{
	if (value)
	{
		delete value;
		value = 0;
	}
}

unsigned char* ASN1Object::Parse(unsigned char* in) 
{
	type = *in++;
	if (*in == 0xFF) return 0;
	if (*in & 0x80)
	{
		int i = *in++ & 0x7F;
		len = 0;
		while (i-- > 0)
		{
			len <<= 8;
			len |= *in++;
		}
	}
	else len = *in++ & 0x7F;
	return in;
}
unsigned char* ASN1Sequence::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in == 0 || type != 0x30) return 0;
	return in;
}
unsigned char* ASN1SetItem::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in == 0 || type != 0x31) return 0;
	return in;
}
unsigned char* ASN1Interger::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in == 0) return 0;
	if (type != 2) return 0;
	if (*in == 0)
	{
		in++;
		len--;
	}
	if (len > 4)
	{
		value_long = new unsigned char[len];
		memcpy(value_long, in, len);
	}
	else
	{
		memcpy(value_short, in, len);
	}
	return in + len;
}
unsigned char* ASN1Bitstring::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in == 0) return 0;
	if (type != 3) return 0;
	return in;
}
unsigned char* ASN1ObjectIdentifier::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in == 0) return 0;
	if (type != 6) return 0;
	if (len > 4)
	{
		oid_long = new unsigned char[len];
		memcpy(oid_long, in, len);
	}
	else
	{
		memcpy(oid_short, in, len);
	}
	return in + len;
}
unsigned char* ASN1CharacterString::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in == 0) return 0;
	if (len < 4)
	{
		memcpy(str_short, in, len);
	}
	else
	{
		str_long = new unsigned char[len + 1];
		memcpy(str_long, in, len);
		str_long[len] = 0;
	}
	return in + len;
}
unsigned char* CertificateVersion::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in[0] == 2 && in[1] == 1)
	{
		ver = in[2];
		if (ver > 2) return 0;
		return in + 3;
	}
	return 0;
}
unsigned char* AlgorithmIdentifier::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = algorithm.Parse(in);
	if (in == 0) return 0;
	if (algorithm.PKCS1Algorithm() == 0) return 0;
	in = param.Parse(in);
	if (in == 0) return 0;
	if (param.ASN1Tag() != 5 || param.ASN1Len() != 0) return 0;
	if (in != end) return 0;
	return in;
}
unsigned char* RDNSequenceItem::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = item.Parse(in);
	if (in == 0) return 0;
	if (item.RDNType() == 0) return 0;
	in = str.Parse(in);
	if (in != end) return 0;
	return in;
}
unsigned char* RDNSequence::Parse(unsigned char* in)
{
	in = ASN1SetItem::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = item.Parse(in);
	if (in != end) return 0;
	return in;
}
unsigned char* Name::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = head.Parse(in);
	if (in == 0) return 0;
	RDNSequence* last = &head;
	while (in < end)
	{
		RDNSequence* seq = new RDNSequence;
		last->SetNext(seq);
		last = seq;
		in = seq->Parse(in);
		if (in == 0) return 0;
	}
	if (in != end) return 0;
	return in;
}
unsigned char* UTCTime::Parse(unsigned char* in)
{
	in = ASN1Object::Parse(in);
	if (in == 0) return 0;
	if (type != 0x17) return 0;
	if (len > 0x10) return 0;
	memcpy(utcStr, in, len);
	return in + len;
}
unsigned char* Validity::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = notBefore.Parse(in);
	if (in == 0) return 0;
	in = notAfter.Parse(in);
	if (in != end) return 0;
	return in;
}
unsigned char* RSAKeyItem::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = public_mod.Parse(in);
	if (in == 0) return 0;
	in = public_exp.Parse(in);
	if (in != end) return 0;
	return in;
}
unsigned char* RSAKeyInfo::Parse(unsigned char* in)
{
	in = ASN1Bitstring::Parse(in);
	if (in == 0) return 0;		
	unsigned char* end = in + len;
	if (*in == 0) in++;
	in = key.Parse(in);
	if (in != end) return 0;
	return in;
}
unsigned char* SubjectPublicKeyInfo::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = algorithm.Parse(in);
	if (in == 0) return 0;
	in = key.Parse(in);
	if (in != end) return 0;
	return in;
}
unsigned char* CertificateContent::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	unsigned char* p = version.Parse(in);
	if (p) in = p; //Root V1 certificate usually doesn't contain version section.
	in = serial.Parse(in);
	if (in == 0) return 0;
	in = signature.Parse(in);
	if (in == 0) return 0;
	in = issuer.Parse(in);
	if (in == 0) return 0;
	in = validity.Parse(in);
	if (in == 0) return 0;
	in = subject.Parse(in);
	if (in == 0) return 0;
	in = subjectPublicKeyInfo.Parse(in);
	if (in == 0) return 0;
	//Skip extensions.
	return end;
}
unsigned char* SignatureBitstring::Parse(unsigned char* in)
{
	in = ASN1Bitstring::Parse(in);
	if (in == 0) return 0;		
	unsigned char* end = in + len;
	if (*in == 0)
	{
		in++;len--;
	}
	value = new unsigned char[len];
	memcpy(value, in, len);
	in += len;
	if (in != end) return 0;
	return in;
}
unsigned char* CertificateSignature::Parse(unsigned char* in)
{
	in = AlgorithmIdentifier::Parse(in);
	if (in == 0) return 0;
	in = signature.Parse(in);
	return in;
}
unsigned char* Certificate::Parse(unsigned char* in)
{
	in = ASN1Sequence::Parse(in);
	if (in == 0) return 0;
	unsigned char* end = in + len;
	in = certificate.Parse(in);
	if (in == 0) return 0;
	in = signature.Parse(in);
	if (in != end) return 0;
	return in;
}

unsigned char* ASN1Interger::Value()
{
	if (len > 4) return value_long;
	else return value_short;
}

unsigned char ASN1ObjectIdentifier::PKCS1Algorithm()
{		
	if (len != 9) return 0;
	if (oid_long == 0) return 0;
	static const unsigned char pkcs_1_id[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01}; 
	//1.2.840.113549.1.1
	if (memcmp(pkcs_1_id, oid_long, 8) == 0)
	{
		if (oid_long[8] > 14) return 0;
		return oid_long[8];
	}
	return 0;
}
unsigned char ASN1ObjectIdentifier::RDNType()
{
	if (len == 3)
	{
		if (oid_short[0] == 0x55 && oid_short[1] == 0x4)
			return oid_short[2];
		return 0;
	}
	if (len == 0xb)
	{
		static const unsigned char jurisdiction[10] = {0x2B,0x6,0x1,0x4, 0x1,0x82,0x37,0x3C,0x2,0x1};
		if (memcmp(oid_long,jurisdiction,10) == 0)
			return oid_long[10];
		return 0;
	}
	return 0;
}

unsigned int RSAKeyItem::PublicKey(unsigned char* k)
{
	unsigned int l = public_mod.ASN1Len();
	if (k) memcpy(k, public_mod.Value(), l);
	return l;
}
unsigned int RSAKeyInfo::PublicKey(unsigned char* k)
{
	return key.PublicKey(k);
}
unsigned int SubjectPublicKeyInfo::PublicKey(unsigned char* k)
{
	return key.PublicKey(k);
}
unsigned int CertificateContent::PublicKey(unsigned char* k)
{
	return subjectPublicKeyInfo.PublicKey(k);
}
unsigned int Certificate::PublicKey(unsigned char* k)
{
	return certificate.PublicKey(k);
}
