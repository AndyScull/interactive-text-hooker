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

#ifndef ITH_AES256
#define ITH_AES256
void KeyExpansion(unsigned char* key);
void AES256EncryptRound(unsigned char* plain_text, unsigned char* cipher_text, unsigned char* key,unsigned int round);
void AES256Encrypt(unsigned char* plain_text, unsigned char* cipher_text, unsigned char* key);
void AES256Decrypt(unsigned char* plain_text, unsigned char* cipher_text, unsigned char* key);

class AES_CBC_Cipher
{
public:
	AES_CBC_Cipher(unsigned char* key, unsigned char* iv);
	~AES_CBC_Cipher();
	void Init(unsigned char* key, unsigned char* iv);
	void Encrypt(void* in, void* out);
	void Decrypt(void* in, void* out);
private:
	unsigned char cipher_iv[16];
	unsigned char cipher_key[240];
};
#endif