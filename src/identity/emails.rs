



use crate::platform::mail::Email;

fn link(public_url: &str, path: &str, token: &str) -> String {
    format!("{}{path}#token={token}", public_url.trim_end_matches('/'))
}



fn untrusted(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > 80 {
        format!("{}…", flat.chars().take(80).collect::<String>())
    } else {
        flat
    }
}

pub fn verify_email(to: &str, public_url: &str, token: &str) -> Email {
    Email {
        to: to.into(),
        subject: "Confirm your email address".into(),
        body: format!(
            "Confirm your email address for Ultrivly by opening this link:\n\n{}\n\n\
             The link expires in 3 days. If you did not create an account, ignore this email.\n",
            link(public_url, "/verify-email", token)
        ),
    }
}

pub fn password_reset(to: &str, public_url: &str, token: &str) -> Email {
    Email {
        to: to.into(),
        subject: "Reset your password".into(),
        body: format!(
            "Someone asked to reset the password for your Ultrivly account. To choose a new\n\
             password, open this link:\n\n{}\n\n\
             The link expires in 1 hour and works once. If you did not ask for this, ignore\n\
             this email; your password has not changed.\n",
            link(public_url, "/reset-password", token)
        ),
    }
}



pub fn sign_up_attempted(to: &str, public_url: &str) -> Email {
    let base = public_url.trim_end_matches('/');
    Email {
        to: to.into(),
        subject: "Someone tried to sign up with your email".into(),
        body: format!(
            "Someone tried to create an Ultrivly account with this email address, but you\n\
             already have one. Sign in at {base}/sign-in, or reset your password at\n\
             {base}/forgot-password. If this was not you, you can ignore this email.\n"
        ),
    }
}

pub fn password_changed(to: &str) -> Email {
    Email {
        to: to.into(),
        subject: "Your password was changed".into(),
        body: "The password for your Ultrivly account was just changed, and other sessions\n\
               were signed out. If you did not do this, reset your password immediately and\n\
               contact your administrator.\n"
            .into(),
    }
}

pub fn mfa_disabled(to: &str) -> Email {
    Email {
        to: to.into(),
        subject: "Two-step verification was turned off".into(),
        body: "Two-step verification was just turned off for your Ultrivly account. If you\n\
               did not do this, reset your password immediately and contact your administrator.\n"
            .into(),
    }
}

pub fn invitation(to: &str, public_url: &str, token: &str, org_name: &str, inviter: &str) -> Email {
    Email {
        to: to.into(),
        subject: "You have been invited to Ultrivly".into(),
        body: format!(
            "{} invited you to join the organization \"{}\" on Ultrivly.\n\n\
             To accept, sign in or create an account with this email address, then open:\n\n{}\n\n\
             The invitation expires in 7 days. If you were not expecting it, ignore this email.\n",
            untrusted(inviter),
            untrusted(org_name),
            link(public_url, "/accept-invitation", token)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_go_in_the_fragment() {
        let email = password_reset("a@b.co", "https://support.example.com/", "tok");
        assert!(
            email
                .body
                .contains("https://support.example.com/reset-password#token=tok")
        );
    }

    #[test]
    fn untrusted_names_are_flattened_and_shortened() {
        assert_eq!(
            untrusted("Acme\n\nClick here:\r\nevil"),
            "Acme Click here: evil"
        );
        assert_eq!(untrusted(&"x".repeat(200)).chars().count(), 81);
    }
}
