import logging, json, os, base64
from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    RegistrationCredential,
    UserVerificationRequirement,
    AuthenticationCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)

application = Flask(__name__)
app = application
# cors = CORS(app, origins=['http://localhost:3000'])
# cors = CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
cors = CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

def generate_random_challenge(length: int = 32) -> bytes:
    return os.urandom(length)

def bytes_to_base64url(val: bytes) -> str:
    return base64.urlsafe_b64encode(val).decode('utf-8').rstrip('=')

@application.route('/')
def hello_world():
    return "Success Elastic BeanStalk Hello World"

@application.route('/generate_registration_options', methods=['POST'])
@cross_origin()
def generate_complex_options():
    logging.info("generate_complex_options Start")
    logging.info(f"Headers: {request.headers}")
    logging.info(f"Body: {request.data}")
    data = request.json
    complex_registration_options = generate_registration_options(
        rp_id=data["rp_id"],
        rp_name=data["rp_name"],
        user_id=data["user_id"].encode('utf-8'),
        user_name=data["user_name"],
        user_display_name=data["user_display_name"],
        attestation=AttestationConveyancePreference.DIRECT,
        # authenticator_selection=AuthenticatorSelectionCriteria(
        #     # authenticator_attachment=AuthenticatorAttachment.PLATFORM, # only device
        #     authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
        #     # resident_key=ResidentKeyRequirement.REQUIRED,
        # ),
        challenge=generate_random_challenge(),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=b"1234567892"),
        ],
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_512,
            COSEAlgorithmIdentifier.ECDSA_SHA_256,  # Add this line
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # Add this line
        ],
        timeout=30000,
    )

    logging.info("generate_complex_options End")
    return options_to_json(complex_registration_options)


@application.route('/verify_registration', methods=['POST'])
@cross_origin()
def verify_registration():
    logging.info("verify_registration Start")
    data = request.json
    credential_data = data["credential"]

    credential_data['raw_id'] = base64url_to_bytes(credential_data.pop('rawId'))

    # responseフィールドをAuthenticatorAttestationResponseに変換
    response_data = credential_data.pop('response')
    credential_data['response'] = AuthenticatorAttestationResponse(
        client_data_json=base64url_to_bytes(response_data['clientDataJSON']),
        attestation_object=base64url_to_bytes(response_data['attestationObject'])
    )

    # 不要なフィールドを削除
    allowed_fields = {'id', 'raw_id', 'response', 'type', 'authenticator_attachment'}
    credential_data = {k: v for k, v in credential_data.items() if k in allowed_fields}

    registration_verification = verify_registration_response(
        credential=RegistrationCredential(**credential_data),
        expected_challenge=base64url_to_bytes(data["expectedChallenge"]),
        expected_origin=data["expectedOrigin"],
        expected_rp_id=data["expectedRpId"],
        require_user_verification=True,
    )
   
    response_dict = {
        "credential_id": bytes_to_base64url(registration_verification.credential_id),
        "credential_public_key": bytes_to_base64url(registration_verification.credential_public_key),
        "sign_count": registration_verification.sign_count,
        "user_verified": registration_verification.user_verified,
        "attestation_object": bytes_to_base64url(registration_verification.attestation_object),
        "aaguid": registration_verification.aaguid,
        "fmt": registration_verification.fmt,
        "credential_type": registration_verification.credential_type,
        "credential_device_type": registration_verification.credential_device_type,
        "credential_backed_up": registration_verification.credential_backed_up,
    }

    logging.info("verify_registration End")
    return jsonify(response_dict)

@application.route('/generate_auth_options', methods=['POST'])
@cross_origin()
def generate_auth_options():
    logging.info("generate_authentication_options Start")
    data = request.json
    stored_credential_data = data.get("stored_credential_data", {})
    id_bytes = base64url_to_bytes(stored_credential_data.get("id", ""))
    stored_descriptor = PublicKeyCredentialDescriptor(
        id=id_bytes,
        type="public-key",
        transports=stored_credential_data.get("transports", [])
    )

    complex_authentication_options = generate_authentication_options(
        rp_id=data["rp_id"],
        challenge=bytes(data["challenge"], "utf-8"),
        timeout=30000,
        allow_credentials=[stored_descriptor],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    logging.info("complex_authentication_options: %s",
                 options_to_json(complex_authentication_options))
    logging.info("generate_authentication_options End")
    return options_to_json(complex_authentication_options)


@application.route('/verify_authentication_response', methods=['POST'])
@cross_origin()
def verify_authentication():
    logging.info("verify_authentication Start")
    data = request.json
    credential_data = data["credential"]
    credential_public_key = credential_data["publicKey"]
    credential_current_sign_count = int(credential_data["signCount"])

    # rawIdをraw_idに変換
    credential_data['raw_id'] = base64url_to_bytes(credential_data.pop('rawId'))

    # 修正箇所
    response_data = credential_data.pop('response')
    credential_data['response'] = AuthenticatorAssertionResponse(
        client_data_json=base64url_to_bytes(response_data['clientDataJSON']),
        authenticator_data=base64url_to_bytes(response_data['authenticatorData']),
        signature=base64url_to_bytes(response_data['signature']),
        user_handle=base64url_to_bytes(response_data['userHandle']) if 'userHandle' in response_data else None
    )

    # 不要なフィールドを削除
    allowed_fields = {'id', 'raw_id', 'response', 'type', 'authenticator_attachment'}
    credential_data = {k: v for k, v in credential_data.items() if k in allowed_fields}

    authentication_verification = verify_authentication_response(
        credential=AuthenticationCredential(**credential_data),
        expected_challenge=base64url_to_bytes(data["expectedChallenge"]),
        expected_origin=data["expectedOrigin"],
        expected_rp_id=data["expectedRpId"],
        credential_public_key=base64url_to_bytes(credential_public_key),
        credential_current_sign_count=credential_current_sign_count,
        require_user_verification=True,
    )

    response_dict = {
        "credential_id": bytes_to_base64url(authentication_verification.credential_id),
        "new_sign_count": authentication_verification.new_sign_count,
        "credential_device_type": authentication_verification.credential_device_type,
        "credential_backed_up": authentication_verification.credential_backed_up,
    }

    logging.info("verify_registration End")
    return jsonify(response_dict)

if __name__ == '__main__':
    # logging.basicConfig(level=logging.INFO)
    app.run()