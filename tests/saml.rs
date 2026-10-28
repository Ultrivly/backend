use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use samael::crypto::{CertificateDer, Crypto, CryptoProvider};
use samael::idp::response_builder::{ResponseAttribute, build_response_template};
use samael::idp::sp_extractor::RequiredAttribute;
use samael::idp::{CertificateParams, IdentityProvider, KeyType, Rsa};
use samael::traits::ToXml;
use sqlx::PgPool;
use ultrivly::audit::Actor;
use ultrivly::config::Deployment;
use ultrivly::identity::accounts::SignIn;
use ultrivly::identity::saml::NewSamlConnection;
use ultrivly::identity::sessions::{AuthMethod, ClientInfo};
use ultrivly::identity::sso::{Sso, SsoError, SsoOutcome};
use ultrivly::platform::net::{HttpClient, NetPolicy};
use ultrivly::platform::secrets::Secrets;
use uuid::Uuid;

mod common;
use common::{create_org, role_id};

const IDP_ENTITY: &str = "https://idp.example.test";

struct Idp {
    key: IdentityProvider,
    cert: CertificateDer,
}

impl Idp {
    fn new() -> Self {
        let key = IdentityProvider::generate_new(KeyType::Rsa(Rsa::Rsa2048)).unwrap();
        let cert = key
            .create_certificate(&CertificateParams {
                common_name: "idp.example.test",
                issuer_name: "idp.example.test",
                days_until_expiration: 30,
            })
            .unwrap();
        Self { key, cert }
    }

    fn metadata(&self) -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{IDP_ENTITY}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            STANDARD.encode(self.cert.der_data())
        )
    }

    fn respond(
        &self,
        sso: &Sso,
        connection: Uuid,
        request_id: &str,
        email: &str,
        audience: Option<&str>,
    ) -> String {
        self.sign(sso, connection, request_id, email, audience, true)
    }

    fn sign(
        &self,
        sso: &Sso,
        connection: Uuid,
        request_id: &str,
        email: &str,
        audience: Option<&str>,
        sha256_digest: bool,
    ) -> String {
        let entity = sso.saml_entity_id(connection);
        let attributes = [ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".into(),
                format: None,
            },
            value: email,
        }];
        let template = build_response_template(
            &self.cert,
            &format!("subject-{email}"),
            audience.unwrap_or(&entity),
            IDP_ENTITY,
            &sso.saml_acs_url(connection),
            request_id,
            &attributes,
        );
        let mut xml = template.to_string().unwrap();
        let expires = (chrono::Utc::now() + chrono::Duration::minutes(5))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let open_tag = xml
            .find("SubjectConfirmationData ")
            .expect("subject confirmation");
        xml.insert_str(
            open_tag + "SubjectConfirmationData ".len(),
            &format!("NotOnOrAfter=\"{expires}\" "),
        );
        if sha256_digest {
            xml = xml.replace(
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            );
        }
        let signed = Crypto::sign_xml(
            xml.as_str(),
            self.key.export_private_key_der().unwrap().as_slice(),
        )
        .unwrap();
        STANDARD.encode(signed)
    }
}

fn sso() -> Sso {
    let http = HttpClient::new(NetPolicy::new(Deployment::Cloud, &[])).unwrap();
    Sso::new(
        Secrets::from_base64_key(&Secrets::generate_key()).unwrap(),
        http,
        "https://ultrivly.test",
        vec![],
    )
    .unwrap()
}

async fn connect(pool: &PgPool, sso: &Sso, idp: &Idp) -> (Uuid, Uuid) {
    let (org, owner) = create_org(pool, "acme").await;
    let agent = role_id(pool, org.org_id, "agent").await;
    let mut conn = pool.acquire().await.unwrap();
    let id = sso
        .create_saml_connection(
            &mut conn,
            org.org_id,
            Actor::User(owner),
            NewSamlConnection {
                name: "Acme SAML",
                idp_metadata_xml: &idp.metadata(),
                email_domains: &["acme.test"],
                jit_provisioning: true,
                default_role_id: Some(agent),
                enforced: false,
            },
        )
        .await
        .unwrap();
    (org.org_id, id)
}

#[sqlx::test]
async fn signed_response_provisions_and_signs_in(pool: PgPool) {
    let (sso, idp) = (sso(), Idp::new());
    let (org_id, connection) = connect(&pool, &sso, &idp).await;
    let mut conn = pool.acquire().await.unwrap();

    let (url, request_id) = sso
        .begin_saml(&mut conn, connection, Some("/cases"), None)
        .await
        .unwrap();
    assert!(url.starts_with("https://idp.example.test/sso?SAMLRequest="));
    assert!(request_id.len() > 60);

    let response = idp.respond(&sso, connection, &request_id, "alice@acme.test", None);
    let outcome = sso
        .complete_saml(
            &mut conn,
            connection,
            &response,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap();
    let SsoOutcome::SignedIn {
        sign_in: SignIn::Complete(new),
        redirect_to,
    } = outcome
    else {
        panic!("expected a completed sign-in");
    };
    assert_eq!(redirect_to.as_deref(), Some("/cases"));
    assert_eq!(
        new.session.method,
        AuthMethod::Sso {
            connection_id: connection
        }
    );

    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
                        WHERE m.org_id = $1 AND u.email = 'alice@acme.test')",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(member);

    let metadata = sso.saml_sp_metadata(&mut conn, connection).await.unwrap();
    assert!(metadata.contains(&sso.saml_acs_url(connection)));
}

#[sqlx::test]
async fn requests_and_assertions_are_single_use(pool: PgPool) {
    let (sso, idp) = (sso(), Idp::new());
    let (_, connection) = connect(&pool, &sso, &idp).await;
    let mut conn = pool.acquire().await.unwrap();
    let (_, request_id) = sso
        .begin_saml(&mut conn, connection, None, None)
        .await
        .unwrap();
    let response = idp.respond(&sso, connection, &request_id, "alice@acme.test", None);
    sso.complete_saml(
        &mut conn,
        connection,
        &response,
        &request_id,
        &ClientInfo::default(),
    )
    .await
    .unwrap();

    let err = sso
        .complete_saml(
            &mut conn,
            connection,
            &response,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::InvalidState), "{err}");

    sqlx::query(
        "INSERT INTO saml_requests (id, sso_connection_id, expires_at) VALUES ($1, $2, now() + interval '5 minutes')",
    )
    .bind(&request_id)
    .bind(connection)
    .execute(&pool)
    .await
    .unwrap();
    let err = sso
        .complete_saml(
            &mut conn,
            connection,
            &response,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, SsoError::Provider(m) if m.contains("already used")),
        "{err}"
    );
}

#[sqlx::test]
async fn forged_tampered_and_misaddressed_responses_are_rejected(pool: PgPool) {
    let (sso, idp) = (sso(), Idp::new());
    let (_, connection) = connect(&pool, &sso, &idp).await;
    let mut conn = pool.acquire().await.unwrap();

    let impostor = Idp::new();
    let (_, request_id) = sso
        .begin_saml(&mut conn, connection, None, None)
        .await
        .unwrap();
    let forged = impostor.respond(&sso, connection, &request_id, "alice@acme.test", None);
    let err = sso
        .complete_saml(
            &mut conn,
            connection,
            &forged,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Provider(_)), "{err}");

    let (_, request_id) = sso
        .begin_saml(&mut conn, connection, None, None)
        .await
        .unwrap();
    let genuine = idp.respond(&sso, connection, &request_id, "alice@acme.test", None);
    let xml = String::from_utf8(STANDARD.decode(&genuine).unwrap()).unwrap();
    let tampered = STANDARD.encode(xml.replace("alice@acme.test", "mallory@acme.test"));
    let err = sso
        .complete_saml(
            &mut conn,
            connection,
            &tampered,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Provider(_)), "{err}");

    let (_, request_id) = sso
        .begin_saml(&mut conn, connection, None, None)
        .await
        .unwrap();
    let elsewhere = idp.respond(
        &sso,
        connection,
        &request_id,
        "alice@acme.test",
        Some("https://other-service.example/metadata"),
    );
    let err = sso
        .complete_saml(
            &mut conn,
            connection,
            &elsewhere,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Provider(_)), "{err}");

    let (_, request_id) = sso
        .begin_saml(&mut conn, connection, None, None)
        .await
        .unwrap();
    let weak_digest = idp.sign(
        &sso,
        connection,
        &request_id,
        "alice@acme.test",
        None,
        false,
    );
    let err = sso
        .complete_saml(
            &mut conn,
            connection,
            &weak_digest,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Provider(_)), "{err}");

    let (_, request_id) = sso
        .begin_saml(&mut conn, connection, None, None)
        .await
        .unwrap();
    let outsider = idp.respond(&sso, connection, &request_id, "eve@evil.test", None);
    let err = sso
        .complete_saml(
            &mut conn,
            connection,
            &outsider,
            &request_id,
            &ClientInfo::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::EmailDomainNotAllowed), "{err}");
}

#[sqlx::test]
async fn metadata_without_a_signing_certificate_is_refused(pool: PgPool) {
    let sso = sso();
    let (org, owner) = create_org(&pool, "acme").await;
    let mut conn = pool.acquire().await.unwrap();
    let unsigned = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
    );
    for xml in [unsigned.as_str(), "<not-metadata/>"] {
        let err = sso
            .create_saml_connection(
                &mut conn,
                org.org_id,
                Actor::User(owner),
                NewSamlConnection {
                    name: "Bad",
                    idp_metadata_xml: xml,
                    email_domains: &[],
                    jit_provisioning: false,
                    default_role_id: None,
                    enforced: false,
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SsoError::Invalid {
                    field: "idp_metadata_xml",
                    ..
                }
            ),
            "{err}"
        );
    }
}
