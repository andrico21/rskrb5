#![expect(missing_docs, reason = "lint-migration: upstream baseline at ee9cb04")]
#![cfg(feature = "tokio")]

use core::{error::Error, time::Duration};
#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::unused_trait_names,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
use std::{
    env,
    ffi::OsStr,
    fs,
    net::{TcpListener, TcpStream, ToSocketAddrs},
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5::{
    client::{
        ApReqOptions, KdcProtocol, Principal, TgsRepSession, TokioClient,
        build_ap_req_with_confounder,
    },
    config::Config,
    crypto::KerberosEtype,
    keytab::Keytab,
    service::ServiceValidator,
};

#[path = "support/env.rs"]
mod child_env;

const USER_REALM: &str = "USER.GOKRB5";
const RESOURCE_REALM: &str = "RES.GOKRB5";
const TESTUSER1: &str = "testuser1";
const TESTUSER2: &str = "testuser2";
const TESTUSER3: &str = "testuser3";
const SYSHTTP: &str = "sysHTTP";
const USER_SERVICE_HOST: &str = "user2.user.gokrb5";
const RESOURCE_SERVICE_HOST: &str = "host.res.gokrb5";
const AES128_ETYPE: i32 = 17;
const AES256_ETYPE: i32 = 18;
const RC4_HMAC_ETYPE: i32 = 23;
const AD_FIXTURE_ETYPES: [i32; 3] = [AES128_ETYPE, AES256_ETYPE, RC4_HMAC_ETYPE];

const KEYTAB_TESTUSER1_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100110010528b8ba0ae5131fbf71f6ddc5870cdce000000010000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c275010012002016475f89eba70e62af20a20e7bf3ca4ccad5ae22485c93ffb133650bc6f12585000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100130010a3ddea306fa06c068bc3e1fcf4b280ca000000010000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c27501001400205d2a66a8af5142db59bcaabac8310777bf60a85e8881469e2063bba4dff0c00a000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200110010528b8ba0ae5131fbf71f6ddc5870cdce000000020000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c275020012002016475f89eba70e62af20a20e7bf3ca4ccad5ae22485c93ffb133650bc6f12585000000020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200130010a3ddea306fa06c068bc3e1fcf4b280ca000000020000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c27502001400205d2a66a8af5142db59bcaabac8310777bf60a85e8881469e2063bba4dff0c00a00000002";
const KEYTAB_TESTUSER2_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f30100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f30100110010a771a31fae504621fffc644a521e0cee000000010000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001200203262b201af7ec73c77bbee75a4ff10950cf2bda56529ead30ced4f0f0b9a591d000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001300104be17a4cf1761f0494475617f671fa6a000000010000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001400208b1c60589b6c0d78d5e8fe265e92c2babf920a6a2828c37fc343e43497ad9fab000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a0200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a0200110010a771a31fae504621fffc644a521e0cee000000020000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001200203262b201af7ec73c77bbee75a4ff10950cf2bda56529ead30ced4f0f0b9a591d000000020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001300104be17a4cf1761f0494475617f671fa6a000000020000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001400208b1c60589b6c0d78d5e8fe265e92c2babf920a6a2828c37fc343e43497ad9fab00000002";
const KEYTAB_TESTUSER3_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba950100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010011001025b79e18723ecd0fdf76c3a5bb21d5dd000000010000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba950100120020c98c6dcc3ee520d5712aba339b2aa1930414b24fb52b9f70bf46259a57c1740b000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010013001007f06e524ee5d738b5bb464c876a5087000000010000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010014002024cb938c683c9fcbe548f2febc93f8090fbaf44541751fc2b781e453dba36a11000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d0200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020011001025b79e18723ecd0fdf76c3a5bb21d5dd000000020000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d0200120020c98c6dcc3ee520d5712aba339b2aa1930414b24fb52b9f70bf46259a57c1740b000000020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020013001007f06e524ee5d738b5bb464c876a5087000000020000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020014002024cb938c683c9fcbe548f2febc93f8090fbaf44541751fc2b781e453dba36a1100000002";
const KEYTAB_SYSHTTP_RES_GOKRB5: &str = "0502000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200170010084768c373663b3bef1f6385883cf7ff00000002000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200110010c622e44a32022f4cb81775263151140d00000002000000480001000a5245532e474f4b524235000773797348545450000000015e7a7e2f02001200209da0dc4802bf5d375dfe2a77ddfc5065b3bf789126c2dc89ff4c2aa90dfa43ce00000002000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200130010541beb216c1cdf22ef7c2225066a385e00000002000000480001000a5245532e474f4b524235000773797348545450000000015e7a7e2f02001400205f0983acd70fcaee0acb7ac4a14f8ad89f3a35915914e696200370637d8fef2300000002";

static AD_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct AdKeytabFixture {
    label: &'static str,
    default_hex: &'static str,
    path_env: &'static str,
    hex_env: &'static str,
    base64_env: &'static str,
}

const TESTUSER1_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "testuser1@USER.GOKRB5",
    default_hex: KEYTAB_TESTUSER1_USER_GOKRB5,
    path_env: "TEST_AD_TESTUSER1_KEYTAB_PATH",
    hex_env: "TEST_AD_TESTUSER1_KEYTAB_HEX",
    base64_env: "TEST_AD_TESTUSER1_KEYTAB_BASE64",
};

const TESTUSER2_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "testuser2@USER.GOKRB5",
    default_hex: KEYTAB_TESTUSER2_USER_GOKRB5,
    path_env: "TEST_AD_TESTUSER2_KEYTAB_PATH",
    hex_env: "TEST_AD_TESTUSER2_KEYTAB_HEX",
    base64_env: "TEST_AD_TESTUSER2_KEYTAB_BASE64",
};

const TESTUSER3_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "testuser3@USER.GOKRB5",
    default_hex: KEYTAB_TESTUSER3_USER_GOKRB5,
    path_env: "TEST_AD_TESTUSER3_KEYTAB_PATH",
    hex_env: "TEST_AD_TESTUSER3_KEYTAB_HEX",
    base64_env: "TEST_AD_TESTUSER3_KEYTAB_BASE64",
};

const SYSHTTP_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "sysHTTP@RES.GOKRB5",
    default_hex: KEYTAB_SYSHTTP_RES_GOKRB5,
    path_env: "TEST_AD_SYSHTTP_KEYTAB_PATH",
    hex_env: "TEST_AD_SYSHTTP_KEYTAB_HEX",
    base64_env: "TEST_AD_SYSHTTP_KEYTAB_BASE64",
};

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn active_directory_keytab_login() -> Result<(), Box<dyn Error>> {
    let _guard = AD_LOCK.lock().expect("AD integration test lock");
    if !ad_enabled()? {
        return Ok(());
    }

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, false)?;
        let tgt = client.login().await?;

        assert_eq!(tgt.client, Principal::user(USER_REALM, TESTUSER1));
        assert_eq!(tgt.service, Principal::tgt_service(USER_REALM));
        assert_eq!(tgt.session_key.etype, AES256_ETYPE);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn active_directory_keytab_login_without_preauth() -> Result<(), Box<dyn Error>> {
    let _guard = AD_LOCK.lock().expect("AD integration test lock");
    if !ad_enabled()? {
        return Ok(());
    }

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER3, testuser3_keytab()?, false)?;
        let tgt = client.login().await?;

        assert_eq!(tgt.client, Principal::user(USER_REALM, TESTUSER3));
        assert_eq!(tgt.service, Principal::tgt_service(USER_REALM));
        assert_eq!(tgt.session_key.etype, AES256_ETYPE);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn active_directory_service_ticket_validates_user_domain_pac() -> Result<(), Box<dyn Error>> {
    let _guard = AD_LOCK.lock().expect("AD integration test lock");
    if !ad_enabled()? {
        return Ok(());
    }

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, false)?;
        client.login().await?;

        let ticket = client
            .get_service_ticket(http_service(USER_REALM, USER_SERVICE_HOST))
            .await?;
        assert_eq!(ticket.service.name(), format!("HTTP/{USER_SERVICE_HOST}"));
        assert_eq!(ticket.session_key.etype, AES256_ETYPE);

        let service_keytab = testuser2_keytab()?;
        let validated = validate_service_ticket(&ticket, &service_keytab, [TESTUSER2])?;
        let pac = validated.pac.as_ref().expect("AD service ticket has a PAC");
        let credentials = pac.ad_credentials().expect("PAC has validation info");
        assert_eq!(credentials.logon_domain_name, "USER");

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn active_directory_trust_resource_domain_service_ticket_validates_pac()
-> Result<(), Box<dyn Error>> {
    let _guard = AD_LOCK.lock().expect("AD integration test lock");
    if !ad_enabled()? {
        return Ok(());
    }

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, true)?;
        client.login().await?;

        let ticket = client
            .get_service_ticket(http_service(RESOURCE_REALM, RESOURCE_SERVICE_HOST))
            .await?;
        assert_eq!(
            ticket.service.name(),
            format!("HTTP/{RESOURCE_SERVICE_HOST}")
        );
        assert_eq!(ticket.session_key.etype, RC4_HMAC_ETYPE);

        let service_keytab = syshttp_keytab()?;
        let validated = validate_service_ticket(&ticket, &service_keytab, [SYSHTTP])?;
        let pac = validated.pac.as_ref().expect("AD service ticket has a PAC");
        let credentials = pac.ad_credentials().expect("PAC has validation info");
        assert_eq!(credentials.effective_name, TESTUSER1);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        unused_results,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn active_directory_trust_user_domain_service_ticket_validates_pac() -> Result<(), Box<dyn Error>> {
    let _guard = AD_LOCK.lock().expect("AD integration test lock");
    if !ad_enabled()? {
        return Ok(());
    }

    runtime().block_on(async {
        let mut client = ad_client(TESTUSER1, testuser1_keytab()?, true)?;
        client.login().await?;

        let ticket = client
            .get_service_ticket(http_service(USER_REALM, USER_SERVICE_HOST))
            .await?;
        assert_eq!(ticket.service.name(), format!("HTTP/{USER_SERVICE_HOST}"));

        let service_keytab = testuser2_keytab()?;
        let validated = validate_service_ticket(&ticket, &service_keytab, [TESTUSER2])?;
        let pac = validated.pac.as_ref().expect("AD service ticket has a PAC");
        let credentials = pac.ad_credentials().expect("PAC has validation info");
        assert_eq!(credentials.effective_name, TESTUSER1);

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn embedded_ad_keytabs_cover_required_principals_and_enctypes() -> Result<(), Box<dyn Error>> {
    assert_ad_keytab_fixture(TESTUSER1_KEYTAB, USER_REALM, TESTUSER1)?;
    assert_ad_keytab_fixture(TESTUSER2_KEYTAB, USER_REALM, TESTUSER2)?;
    assert_ad_keytab_fixture(TESTUSER3_KEYTAB, USER_REALM, TESTUSER3)?;
    assert_ad_keytab_fixture(SYSHTTP_KEYTAB, RESOURCE_REALM, SYSHTTP)?;
    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn assert_ad_keytab_fixture(
    fixture: AdKeytabFixture,
    realm: &str,
    principal: &str,
) -> Result<(), Box<dyn Error>> {
    let keytab = keytab(fixture.default_hex)?;
    assert_eq!(keytab.version(), 2, "{} uses keytab v2", fixture.label);

    for etype in AD_FIXTURE_ETYPES {
        let (key, kvno) = keytab
            .find_key(&[principal], realm, 0, etype)
            .map_err(|error| {
                ad_gate_error(format!(
                    "embedded AD keytab {} is missing {principal}@{realm} etype {etype}: {error}",
                    fixture.label
                ))
            })?;
        assert_eq!(
            key.value.len(),
            expected_key_len(etype),
            "{} has the expected etype {etype} key length",
            fixture.label
        );
        assert!(
            kvno > 0,
            "{} etype {etype} resolves to a nonzero kvno",
            fixture.label
        );
    }

    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::unreachable,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn expected_key_len(etype: i32) -> usize {
    match etype {
        AES128_ETYPE | RC4_HMAC_ETYPE => 16,
        AES256_ETYPE => 32,
        _ => unreachable!("AD fixture etype list is fixed"),
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::print_stderr,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn ad_enabled() -> Result<bool, Box<dyn Error>> {
    let required = ad_required();
    if !ad_prefetch_gate() {
        let message = "skipping AD integration test; set TESTAD=1 to enable";
        if required {
            return Err(ad_gate_error(format!(
                "{message}; TESTAD_REQUIRED=1 forbids soft skips"
            )));
        }
        eprintln!("{message}");
        return Ok(false);
    }

    let user_kdc = ad_user_kdc_addr();
    let resource_kdc = ad_resource_kdc_addr();

    if !tcp_reachable(&user_kdc, "USER realm KDC") {
        let message = format!("skipping AD integration test; cannot reach user KDC at {user_kdc}");
        if required {
            return Err(ad_gate_error(format!(
                "{message}; TESTAD_REQUIRED=1 forbids soft skips"
            )));
        }
        eprintln!("{message}");
        return Ok(false);
    }

    if !tcp_reachable(&resource_kdc, "RESOURCE realm KDC") {
        let message =
            format!("skipping AD integration test; cannot reach resource KDC at {resource_kdc}");
        if required {
            return Err(ad_gate_error(format!(
                "{message}; TESTAD_REQUIRED=1 forbids soft skips"
            )));
        }
        eprintln!("{message}");
        return Ok(false);
    }

    Ok(true)
}

fn ad_prefetch_gate() -> bool {
    env::var("TESTAD").as_deref() == Ok("1")
}

fn ad_required() -> bool {
    env::var("TESTAD_REQUIRED").as_deref() == Ok("1")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn ad_gate_error(message: String) -> Box<dyn Error> {
    std::io::Error::other(message).into()
}

fn ad_user_kdc_addr() -> String {
    env_value(
        &["TEST_AD_USER_KDC_ADDR", "TEST_AD_KDC_ADDR"],
        "192.168.88.100:88",
    )
}

fn ad_resource_kdc_addr() -> String {
    env_value(
        &["TEST_AD_RESOURCE_KDC_ADDR", "TEST_AD_RES_KDC_ADDR"],
        "192.168.88.101:88",
    )
}

fn ad_user_admin_addr() -> String {
    env_value(
        &["TEST_AD_USER_ADMIN_ADDR", "TEST_AD_ADMIN_ADDR"],
        "192.168.88.100:464",
    )
}

fn ad_resource_admin_addr() -> String {
    env_value(
        &["TEST_AD_RESOURCE_ADMIN_ADDR", "TEST_AD_RES_ADMIN_ADDR"],
        "192.168.88.101:464",
    )
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::print_stderr,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn tcp_reachable(endpoint: &str, label: &str) -> bool {
    let mut addrs = match endpoint.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(error) => {
            eprintln!("failed to resolve {label} {endpoint}: {error}");
            return false;
        }
    };
    let timeout = Duration::from_secs(1);

    addrs.any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn ad_client(user: &str, keytab: Keytab, rc4: bool) -> Result<TokioClient, Box<dyn Error>> {
    Ok(TokioClient::with_keytab(
        ad_config(rc4)?,
        KdcProtocol::Auto,
        Principal::user(USER_REALM, user),
        keytab,
    ))
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::needless_raw_strings,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn ad_config(rc4: bool) -> Result<Config, Box<dyn Error>> {
    let user_kdc = ad_user_kdc_addr();
    let user_admin = ad_user_admin_addr();
    let resource_kdc = ad_resource_kdc_addr();
    let resource_admin = ad_resource_admin_addr();
    let rc4_options = if rc4 {
        r#"
  allow_weak_crypto = true
  canonicalize = true
  default_tkt_enctypes = rc4-hmac
  default_tgs_enctypes = rc4-hmac
  permitted_enctypes = rc4-hmac
"#
    } else {
        ""
    };

    Ok(Config::parse(&format!(
        r#"[libdefaults]
  default_realm = {USER_REALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = false
{rc4_options}

[realms]
 {USER_REALM} = {{
  kdc = {user_kdc}
  admin_server = {user_admin}
  default_domain = user.gokrb5
 }}
 {RESOURCE_REALM} = {{
  kdc = {resource_kdc}
  admin_server = {resource_admin}
  default_domain = res.gokrb5
 }}

[domain_realm]
 .user.gokrb5 = {USER_REALM}
 user.gokrb5 = {USER_REALM}
 .res.gokrb5 = {RESOURCE_REALM}
 res.gokrb5 = {RESOURCE_REALM}
"#,
    ))?)
}

fn env_value(names: &[&str], default: &str) -> String {
    names
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| default.to_owned())
}

fn http_service(realm: &str, host: &str) -> Principal {
    Principal::new(realm, 2, ["HTTP", host])
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn validate_service_ticket<const N: usize>(
    ticket: &TgsRepSession,
    keytab: &Keytab,
    keytab_principal: [&str; N],
) -> Result<rskrb5::service::ValidatedApReq, Box<dyn Error>> {
    let etype =
        KerberosEtype::from_etype_id(ticket.session_key.etype).expect("ticket etype is supported");
    let confounder = vec![0x42; etype.confounder_len()];
    let timestamp = SystemTime::now();
    let ap_req =
        build_ap_req_with_confounder(ticket, ApReqOptions::new(), timestamp, 0, &confounder)?;
    let mut validator = ServiceValidator::new(keytab)
        .with_now(timestamp)
        .with_keytab_principal(keytab_principal);
    Ok(validator.validate_ap_req(&ap_req.der)?)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn testuser1_keytab() -> Result<Keytab, Box<dyn Error>> {
    ad_keytab(TESTUSER1_KEYTAB)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn testuser2_keytab() -> Result<Keytab, Box<dyn Error>> {
    ad_keytab(TESTUSER2_KEYTAB)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn testuser3_keytab() -> Result<Keytab, Box<dyn Error>> {
    ad_keytab(TESTUSER3_KEYTAB)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn syshttp_keytab() -> Result<Keytab, Box<dyn Error>> {
    ad_keytab(SYSHTTP_KEYTAB)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn ad_keytab(fixture: AdKeytabFixture) -> Result<Keytab, Box<dyn Error>> {
    if let Some(path) = env_path_optional(fixture.path_env) {
        let bytes = fs::read(&path).map_err(|error| {
            ad_gate_error(format!(
                "failed to read AD keytab {} from {}={}: {error}",
                fixture.label,
                fixture.path_env,
                path.display()
            ))
        })?;
        return parse_keytab_bytes(
            fixture.label,
            format!("{}={}", fixture.path_env, path.display()),
            &bytes,
        );
    }

    if let Some(hex) = env_string_optional(fixture.hex_env) {
        let bytes = decode_hex_value(&hex).map_err(|error| {
            ad_gate_error(format!(
                "failed to decode AD keytab {} from {}: {error}",
                fixture.label, fixture.hex_env
            ))
        })?;
        return parse_keytab_bytes(fixture.label, fixture.hex_env.to_owned(), &bytes);
    }

    if let Some(base64) = env_string_optional(fixture.base64_env) {
        let bytes = decode_base64_value(&base64).map_err(|error| {
            ad_gate_error(format!(
                "failed to decode AD keytab {} from {}: {error}",
                fixture.label, fixture.base64_env
            ))
        })?;
        return parse_keytab_bytes(fixture.label, fixture.base64_env.to_owned(), &bytes);
    }

    keytab(fixture.default_hex)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn keytab(hex: &str) -> Result<Keytab, Box<dyn Error>> {
    let bytes = decode_hex_value(hex)?;
    Ok(Keytab::parse(&bytes)?)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_errors_doc,
        clippy::needless_pass_by_value,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn parse_keytab_bytes(label: &str, source: String, bytes: &[u8]) -> Result<Keytab, Box<dyn Error>> {
    Keytab::parse(bytes).map_err(|error| {
        ad_gate_error(format!(
            "failed to parse AD keytab {label} from {source}: {error}"
        ))
    })
}

fn env_path_optional(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn env_string_optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::default_numeric_fallback,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn decode_hex_value(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let compact: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !compact.len().is_multiple_of(2) {
        return Err(ad_gate_error(format!(
            "hex input has odd length after whitespace removal: {}",
            compact.len()
        )));
    }

    let mut out = Vec::with_capacity(compact.len() / 2);
    for chunk in compact.as_chunks::<2>().0 {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::arithmetic_side_effects,
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn hex_nibble(byte: u8) -> Result<u8, Box<dyn Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ad_gate_error(format!(
            "invalid hex byte 0x{byte:02x} in keytab override"
        ))),
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "spnego")]
fn decode_base64_value(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use base64::Engine as _;

    let compact: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|error| ad_gate_error(format!("base64 decode error: {error}")))
}

#[cfg_attr(
    any(all(
        not(feature = "default"),
        not(feature = "evaluation"),
        not(feature = "http"),
        feature = "messages",
        not(feature = "serde"),
        not(feature = "spnego"),
        feature = "tokio",
        not(feature = "tower"),
        test
    )),
    expect(
        clippy::missing_errors_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(not(feature = "spnego"))]
fn decode_base64_value(_input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Err(ad_gate_error(
        "base64 keytab overrides require the spnego/default feature".to_owned(),
    ))
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("tokio runtime builds")
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn strict_ad_gate_rejects_missing_testad() {
    const TEST_PATH: &str = "strict_ad_gate_rejects_missing_testad";
    if !child_env::in_child(TEST_PATH) {
        child_env::run_in_child(
            TEST_PATH,
            &[
                ("TESTAD", None),
                ("TESTAD_REQUIRED", Some(OsStr::new("1"))),
                ("TEST_AD_USER_KDC_ADDR", None),
                ("TEST_AD_RESOURCE_KDC_ADDR", None),
                ("TEST_AD_USER_ADMIN_ADDR", None),
                ("TEST_AD_RESOURCE_ADMIN_ADDR", None),
                ("TEST_AD_KDC_ADDR", None),
                ("TEST_AD_RES_KDC_ADDR", None),
                ("TEST_AD_ADMIN_ADDR", None),
                ("TEST_AD_RES_ADMIN_ADDR", None),
            ],
        );
        return;
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    let error = ad_enabled().expect_err("strict AD gate rejects a TESTAD soft skip");
    assert!(
        error
            .to_string()
            .contains("TESTAD_REQUIRED=1 forbids soft skips"),
        "{error}"
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn strict_ad_gate_rejects_malformed_user_kdc_endpoint() {
    const TEST_PATH: &str = "strict_ad_gate_rejects_malformed_user_kdc_endpoint";
    if !child_env::in_child(TEST_PATH) {
        child_env::run_in_child(
            TEST_PATH,
            &[
                ("TESTAD", Some(OsStr::new("1"))),
                ("TESTAD_REQUIRED", Some(OsStr::new("1"))),
                (
                    "TEST_AD_USER_KDC_ADDR",
                    Some(OsStr::new("127.0.0.1:not-a-port")),
                ),
                ("TEST_AD_RESOURCE_KDC_ADDR", None),
                ("TEST_AD_USER_ADMIN_ADDR", None),
                ("TEST_AD_RESOURCE_ADMIN_ADDR", None),
                ("TEST_AD_KDC_ADDR", None),
                ("TEST_AD_RES_KDC_ADDR", None),
                ("TEST_AD_ADMIN_ADDR", None),
                ("TEST_AD_RES_ADMIN_ADDR", None),
            ],
        );
        return;
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    let error = ad_enabled().expect_err("strict AD gate rejects malformed endpoints");
    assert!(
        error.to_string().contains("cannot reach user KDC"),
        "{error}"
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn strict_ad_gate_rejects_unreachable_user_kdc_endpoint() -> Result<(), Box<dyn Error>> {
    const TEST_PATH: &str = "strict_ad_gate_rejects_unreachable_user_kdc_endpoint";
    if !child_env::in_child(TEST_PATH) {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let endpoint = listener.local_addr()?.to_string();
        drop(listener);

        child_env::run_in_child(
            TEST_PATH,
            &[
                ("TESTAD", Some(OsStr::new("1"))),
                ("TESTAD_REQUIRED", Some(OsStr::new("1"))),
                ("TEST_AD_USER_KDC_ADDR", Some(OsStr::new(&endpoint))),
                ("TEST_AD_RESOURCE_KDC_ADDR", None),
                ("TEST_AD_USER_ADMIN_ADDR", None),
                ("TEST_AD_RESOURCE_ADMIN_ADDR", None),
                ("TEST_AD_KDC_ADDR", None),
                ("TEST_AD_RES_KDC_ADDR", None),
                ("TEST_AD_ADMIN_ADDR", None),
                ("TEST_AD_RES_ADMIN_ADDR", None),
            ],
        );
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    let error = ad_enabled().expect_err("strict AD gate rejects unreachable endpoints");
    assert!(
        error.to_string().contains("cannot reach user KDC at"),
        "{error}"
    );

    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn ad_config_uses_endpoint_overrides_and_rc4_trust_options() -> Result<(), Box<dyn Error>> {
    const TEST_PATH: &str = "ad_config_uses_endpoint_overrides_and_rc4_trust_options";
    if !child_env::in_child(TEST_PATH) {
        child_env::run_in_child(
            TEST_PATH,
            &[
                ("TESTAD", None),
                ("TESTAD_REQUIRED", None),
                (
                    "TEST_AD_USER_KDC_ADDR",
                    Some(OsStr::new("192.0.2.10:10088")),
                ),
                (
                    "TEST_AD_RESOURCE_KDC_ADDR",
                    Some(OsStr::new("192.0.2.11:10088")),
                ),
                (
                    "TEST_AD_USER_ADMIN_ADDR",
                    Some(OsStr::new("192.0.2.10:10464")),
                ),
                (
                    "TEST_AD_RESOURCE_ADMIN_ADDR",
                    Some(OsStr::new("192.0.2.11:10464")),
                ),
                ("TEST_AD_KDC_ADDR", None),
                ("TEST_AD_RES_KDC_ADDR", None),
                ("TEST_AD_ADMIN_ADDR", None),
                ("TEST_AD_RES_ADMIN_ADDR", None),
            ],
        );
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    let config = ad_config(false)?;
    assert_eq!(
        config.configured_kdcs(USER_REALM)?,
        &["192.0.2.10:10088".to_owned()]
    );
    assert_eq!(
        config.configured_kdcs(RESOURCE_REALM)?,
        &["192.0.2.11:10088".to_owned()]
    );
    assert_eq!(
        config
            .realm(USER_REALM)
            .expect("USER realm exists")
            .admin_server,
        ["192.0.2.10:10464".to_owned()]
    );
    assert_eq!(
        config
            .realm(RESOURCE_REALM)
            .expect("RESOURCE realm exists")
            .admin_server,
        ["192.0.2.11:10464".to_owned()]
    );
    assert!(!config.libdefaults.allow_weak_crypto);
    assert!(!config.libdefaults.canonicalize);
    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [AES256_ETYPE]);
    assert_eq!(config.libdefaults.default_tgs_enctype_ids, [AES256_ETYPE]);

    let rc4_config = ad_config(true)?;
    assert!(rc4_config.libdefaults.allow_weak_crypto);
    assert!(rc4_config.libdefaults.canonicalize);
    assert_eq!(
        rc4_config.libdefaults.default_tkt_enctype_ids,
        [RC4_HMAC_ETYPE]
    );
    assert_eq!(
        rc4_config.libdefaults.default_tgs_enctype_ids,
        [RC4_HMAC_ETYPE]
    );
    assert_eq!(
        rc4_config.libdefaults.permitted_enctype_ids,
        [RC4_HMAC_ETYPE]
    );

    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        let_underscore_drop,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn ad_keytab_uses_path_override() -> Result<(), Box<dyn Error>> {
    const TEST_PATH: &str = "ad_keytab_uses_path_override";
    if !child_env::in_child(TEST_PATH) {
        let path = temp_keytab_path("testuser1");
        child_env::run_in_child(
            TEST_PATH,
            &[
                (TESTUSER1_KEYTAB.path_env, Some(path.as_os_str())),
                (TESTUSER1_KEYTAB.hex_env, None),
                (TESTUSER1_KEYTAB.base64_env, None),
            ],
        );
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");
    let bytes = decode_hex_value(KEYTAB_TESTUSER1_USER_GOKRB5)?;
    let path = PathBuf::from(
        env::var_os(TESTUSER1_KEYTAB.path_env).expect("the parent test sets the keytab path"),
    );
    fs::write(&path, &bytes)?;

    assert_eq!(testuser1_keytab()?, keytab(KEYTAB_TESTUSER1_USER_GOKRB5)?);

    let _ = fs::remove_file(path);
    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::std_instead_of_core,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn ad_keytab_uses_hex_override() -> Result<(), Box<dyn Error>> {
    const TEST_PATH: &str = "ad_keytab_uses_hex_override";
    if !child_env::in_child(TEST_PATH) {
        let spaced_hex = KEYTAB_TESTUSER2_USER_GOKRB5
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("fixture hex is utf8"))
            .collect::<Vec<_>>()
            .join("\n");
        child_env::run_in_child(
            TEST_PATH,
            &[
                (TESTUSER2_KEYTAB.path_env, None),
                (TESTUSER2_KEYTAB.hex_env, Some(OsStr::new(&spaced_hex))),
                (TESTUSER2_KEYTAB.base64_env, None),
            ],
        );
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    assert_eq!(testuser2_keytab()?, keytab(KEYTAB_TESTUSER2_USER_GOKRB5)?);

    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "spnego")]
#[test]
fn ad_keytab_uses_base64_override() -> Result<(), Box<dyn Error>> {
    use base64::Engine as _;

    const TEST_PATH: &str = "ad_keytab_uses_base64_override";
    if !child_env::in_child(TEST_PATH) {
        let bytes = decode_hex_value(KEYTAB_SYSHTTP_RES_GOKRB5)?;
        let base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        child_env::run_in_child(
            TEST_PATH,
            &[
                (SYSHTTP_KEYTAB.path_env, None),
                (SYSHTTP_KEYTAB.hex_env, None),
                (SYSHTTP_KEYTAB.base64_env, Some(OsStr::new(&base64))),
            ],
        );
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");

    assert_eq!(syshttp_keytab()?, keytab(KEYTAB_SYSHTTP_RES_GOKRB5)?);

    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        clippy::tests_outside_test_module,
        clippy::unwrap_in_result,
        let_underscore_drop,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn ad_keytab_path_override_takes_precedence_over_encoded_values() -> Result<(), Box<dyn Error>> {
    const TEST_PATH: &str = "ad_keytab_path_override_takes_precedence_over_encoded_values";
    if !child_env::in_child(TEST_PATH) {
        let path = temp_keytab_path("testuser3");
        child_env::run_in_child(
            TEST_PATH,
            &[
                (TESTUSER3_KEYTAB.path_env, Some(path.as_os_str())),
                (TESTUSER3_KEYTAB.hex_env, Some(OsStr::new("00"))),
                (TESTUSER3_KEYTAB.base64_env, None),
            ],
        );
        return Ok(());
    }
    let _guard = AD_LOCK.lock().expect("AD integration test lock");
    let path = PathBuf::from(
        env::var_os(TESTUSER3_KEYTAB.path_env).expect("the parent test sets the keytab path"),
    );
    fs::write(&path, decode_hex_value(KEYTAB_TESTUSER3_USER_GOKRB5)?)?;

    assert_eq!(testuser3_keytab()?, keytab(KEYTAB_TESTUSER3_USER_GOKRB5)?);

    let _ = fs::remove_file(path);
    Ok(())
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::absolute_paths,
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
fn temp_keytab_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "rskrb5-ad-{label}-{}-{nanos}.keytab",
        std::process::id()
    ))
}
