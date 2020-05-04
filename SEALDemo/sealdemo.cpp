#include <seal/seal.h>
#include <iostream>

using namespace std;
using namespace seal;

int main() {

	/* Paramètres de sécurité */

	/* On précise quel chiffrement utiliser (ici BFV) */
	EncryptionParameters parms(scheme_type::BFV);
	/* La taille de la clé */
	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	/* Taille de l'espace des messages non chiffrées M
		doit être 2 fois plus grand que les nombres à chiffrer
	*/
	parms.set_plain_modulus(128);

	auto context = SEALContext::Create(parms);

	/* Génération des clés */
	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
	/* Initialisation des interfaces */
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	cout << "On calcule (x^2 + 6) avec x=6.\n";

	int x = 6;
	/* On encode x */
	Plaintext x_plain(to_string(x));

	Ciphertext x_encrypted;
	/* On chiffre x */
	encryptor.encrypt(x_plain, x_encrypted);

	Ciphertext tmp;
	/* On applique la fonction carré x */
	evaluator.square(x_encrypted, tmp);
	Plaintext plain_six("6");
	/* Et on ajoute 6 */
	evaluator.add_plain_inplace(tmp, plain_six);

	Plaintext decrypted_result;
	decryptor.decrypt(tmp, decrypted_result);
	cout << "Le résultat déchiffré est '" << decrypted_result.to_string() << "'.\n";
	
	return 0;
}
