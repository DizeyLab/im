//! Per-user UI strings, ported from iz's `i18n.rs` strategy: one variant
//! per UI phrase, an exhaustive `t` match so a missing translation fails to
//! compile rather than falling through at render time. Only im's real
//! phrases live here — iz's board/task keys stay in iz — plus the
//! settings/preference phrases the preferences wave needs next
//! (`ThemeLabel`, `UiLabel`, `LanguageLabel`, the option labels,
//! `PreferencesLabel`, the password words).

/// A user's stored `language` column ('en' default). Anything not `"tr"` is
/// English — an unrecognized code is not a refusal, just the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Tr,
}

impl Lang {
    pub fn from_code(code: &str) -> Lang {
        match code {
            "tr" => Lang::Tr,
            _ => Lang::En,
        }
    }

    /// The `<html lang>` value, stamped by `layout.rs`'s `shell`.
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Tr => "tr",
        }
    }
}

/// The viewer's language: their stored preference, English when signed out.
pub fn lang_of(user: Option<&im_core::model::User>) -> Lang {
    user.map_or(Lang::En, |u| Lang::from_code(&u.language))
}
/// One variant per UI phrase. A typo'd key fails to compile rather than
/// falling through to nothing at render time.
// The password-change sentences at the enum's tail stay staged: the landing
// and the admin panel refuse through the shared `ErrPassword*` codes, so
// those four have no reader yet.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    // Refusal codes (`pages.rs`'s `error_text`).
    ErrBadLogin,
    ErrBadCode,
    ErrInviteInvalid,
    ErrInviteExpired,
    ErrInviteSpent,
    ErrEmailTaken,
    ErrPasswordTooShort,
    ErrPasswordPersonal,
    ErrPasswordsDiffer,
    ErrEnrollFirst,
    ErrSmtpTest,
    ErrPasswordWrong,
    ErrPasswordSame,
    ErrRateLimited,
    ErrPhotoTooBig,
    ErrNotAnImage,
    ErrNoFile,
    ErrResetInvalid,
    ErrSessionUnknown,
    ErrBadTheme,
    ErrBadUi,
    ErrBadLanguage,
    ErrFallback,

    // Good-news codes (`pages.rs`'s `ok_text`).
    OkReset,
    OkEnrolled,
    OkPhotoSaved,
    OkPhotoRemoved,
    OkSessionRevoked,
    OkDone,

    // Sign-in card and auth pages.
    SignInTitle,
    SignInSub,
    EmailLabel,
    PasswordLabel,
    SignInButton,
    ForgotIt,
    BrandFooter,
    TotpTitle,
    TotpSub,
    CodeLabel,
    VerifyButton,
    InviteTitle,
    InviteSub,
    YourNameLabel,
    PasswordAgainLabel,
    CreateAccountButton,
    InviteDeadTitle,
    BackToSignIn,
    EnrollTitle,
    EnrollSub,
    ConfirmAndSignIn,
    ForgotTitle,
    ForgotSub,
    ForgotSentNote,
    SendLinkButton,
    BackToSignInDash,
    ResetTitle,
    ResetSub,
    NewPasswordAgainLabel,
    TitleSignIn,
    TitleTotp,
    TitleInvited,
    TitleEnroll,
    TitleForgot,
    TitleReset,
    TitleAdmin,

    // Signed-in landing and person page, shared.
    TwoFaOn,
    TwoFaOff,
    AdminChip,
    MemberSinceLabel,
    PublicProfileLink,
    EditProfileLink,
    StatSignIns,
    StatActiveSessions,
    StatConnectedApps,
    SessionsTitle,
    SignOutEverywhere,
    AdminPanelLink,
    ViewPhotoAria,
    ThisSessionChip,
    UnknownDevice,
    DeviceLabel,
    AddressLabel,
    SignedInLabel,
    LastSeenLabel,
    ExpiresLabel,
    SignOutButton,
    RevokeButton,

    // Admin panel nav and banners.
    NavAccount,
    NavUsers,
    NavMail,
    NavSettings,
    NavLogs,
    OkInvited,
    OkRevoked,
    OkDisabled,
    OkEnabled,
    OkSmtpSaved,
    OkSmtpTest,
    OkPasswordChanged,
    OkUninvited,
    OkDeleted,
    OkSettingsSaved,

    // Admin account section.
    AccountTitle,
    SignedInAs,
    TwoFactorOnNote,
    TwoFactorOffNote,
    AccountPasswordNote,

    // Admin users section.
    FlagAdmin,
    FlagDisabled,
    FlagNo2fa,
    FlagInvited,
    AdminSessionsEmpty,
    YouWord,
    EnableWord,
    DisableWord,
    DeleteWord,
    ConfirmEnable,
    ConfirmDisable,
    ConfirmDelete,
    EnableCost,
    DisableCost,
    DeleteCost,
    InvalidateButton,
    InviteLinkNote,
    PeopleTitle,
    EmailCol,
    NameCol,
    RoleMember,
    RoleAdmin,
    InviteButton,

    // Admin settings section.
    SettingsTitle,
    SettingsSub,
    InviteDaysLabel,
    SessionDaysLabel,
    PendingMinutesLabel,
    ResetMinutesLabel,
    LoginAttemptsLabel,
    SaveButton,

    // Admin mail section.
    MailTitle,
    ChipNotConfigured,
    ChipUnchecked,
    ChipRefused,
    ChipConnectedWord,
    HostLabel,
    PortLabel,
    UsernameLabel,
    MailPasswordLabel,
    FromNameLabel,
    FromAddressLabel,
    PasswordSetNote,
    NoPasswordNote,
    CheckConnectionButton,
    SendTestMailButton,
    UncheckedNote,

    // Admin logs section.
    LogsTitle,
    LogsSub,
    WhenCol,
    WhatCol,
    WhoCol,
    DetailCol,

    // Mail (subjects/bodies travel through helpers below).
    InviteMailSubject,
    TestMailSubject,
    TestMailBody,

    // Preference phrases for the later wave (iz-verbatim names where iz has
    // them; iz hardcodes the Instrument/Ledger option labels, so those two
    // and PreferencesLabel are new in iz's style).
    ThemeLabel,
    UiLabel,
    LanguageLabel,
    LightOption,
    DarkOption,
    InstrumentOption,
    LedgerOption,
    PreferencesLabel,
    ChangePassword,
    CurrentPasswordLabel,
    NewPasswordLabel,
    Saved,
    PasswordSaved,
    PWTooShort,
    PWLooksLikeYou,
    PWIsCurrent,
    PWCurrentWrong,

    // Viewer strings owned by `layout.rs`'s `avatar_script` (Change/Remove)
    // and its upload cancel: keys live here so wave-2 converts that file
    // without touching this enum.
    Change,
    Remove,
    CancelUploadLabel,
}

/// The phrase a key names, in a user's language.
pub fn t(lang: Lang, key: Key) -> &'static str {
    use Key::*;
    use Lang::*;
    match (key, lang) {
        (ErrBadLogin, En) => "Wrong email or password.",
        (ErrBadLogin, Tr) => "E-posta ya da parola yanlış.",
        (ErrBadCode, En) => "That code didn't match — try again.",
        (ErrBadCode, Tr) => "Kod eşleşmedi — yeniden dene.",
        (ErrInviteInvalid, En) => "This invite link is not valid.",
        (ErrInviteInvalid, Tr) => "Bu davet bağlantısı geçerli değil.",
        (ErrInviteExpired, En) => "This invite has expired. Ask for a fresh one.",
        (ErrInviteExpired, Tr) => "Bu davetin süresi dolmuş. Yenisini iste.",
        (ErrInviteSpent, En) => "This invite was already used.",
        (ErrInviteSpent, Tr) => "Bu davet zaten kullanıldı.",
        (ErrEmailTaken, En) => "An account with this address already exists.",
        (ErrEmailTaken, Tr) => "Bu adresle zaten bir hesap var.",
        (ErrPasswordTooShort, En) => "The password needs at least 10 characters.",
        (ErrPasswordTooShort, Tr) => "Parola en az 10 karakter olmalı.",
        (ErrPasswordPersonal, En) => "The password can't contain your address or your name.",
        (ErrPasswordPersonal, Tr) => "Parola adresini ya da adını içeremez.",
        (ErrPasswordsDiffer, En) => "The two passwords don't match.",
        (ErrPasswordsDiffer, Tr) => "İki parola eşleşmiyor.",
        (ErrEnrollFirst, En) => "Set up your second factor first.",
        (ErrEnrollFirst, Tr) => "Önce ikinci faktörünü kur.",
        (ErrSmtpTest, En) => "The test mail could not be sent.",
        (ErrSmtpTest, Tr) => "Test postası gönderilemedi.",
        (ErrPasswordWrong, En) => "That's not your current password.",
        (ErrPasswordWrong, Tr) => "Bu mevcut parolan değil.",
        (ErrPasswordSame, En) => "That's already your password.",
        (ErrPasswordSame, Tr) => "Bu zaten parolan.",
        (ErrRateLimited, En) => "Too many tries — wait a while and try again.",
        (ErrRateLimited, Tr) => "Çok fazla deneme — biraz bekleyip yeniden dene.",
        (ErrPhotoTooBig, En) => "That image is over 5 MB.",
        (ErrPhotoTooBig, Tr) => "Bu görsel 5 MB'tan büyük.",
        (ErrNotAnImage, En) => "That file is not an image.",
        (ErrNotAnImage, Tr) => "Bu dosya bir görsel değil.",
        (ErrNoFile, En) => "Choose an image first.",
        (ErrNoFile, Tr) => "Önce bir görsel seç.",
        (ErrResetInvalid, En) => "This reset link is not valid — ask for a fresh one.",
        (ErrResetInvalid, Tr) => "Bu sıfırlama bağlantısı geçerli değil — yenisini iste.",
        (ErrSessionUnknown, En) => "That session is already gone.",
        (ErrSessionUnknown, Tr) => "Bu oturum zaten kapanmış.",
        (ErrBadTheme, En) => "That is not a theme.",
        (ErrBadTheme, Tr) => "Bu bir tema değil.",
        (ErrBadUi, En) => "That is not an interface.",
        (ErrBadUi, Tr) => "Bu bir arayüz değil.",
        (ErrBadLanguage, En) => "That is not a language.",
        (ErrBadLanguage, Tr) => "Bu bir dil değil.",
        (ErrFallback, En) => "Something went wrong. Try again.",
        (ErrFallback, Tr) => "Bir şeyler ters gitti. Yeniden dene.",

        (OkReset, En) => "Password changed — sign in with the new one.",
        (OkReset, Tr) => "Parola değişti — yenisiyle giriş yap.",
        (OkEnrolled, En) => "Two-factor sign-in is on. You're all set.",
        (OkEnrolled, Tr) => "İki faktörlü giriş açık. Her şey hazır.",
        (OkPhotoSaved, En) => "Profile photo updated.",
        (OkPhotoSaved, Tr) => "Profil fotoğrafı güncellendi.",
        (OkPhotoRemoved, En) => "Profile photo removed.",
        (OkPhotoRemoved, Tr) => "Profil fotoğrafı kaldırıldı.",
        (OkSessionRevoked, En) => "Session revoked.",
        (OkSessionRevoked, Tr) => "Oturum kapatıldı.",
        (OkDone, En) => "Done.",
        (OkDone, Tr) => "Tamam.",

        (SignInTitle, En) => "Sign in",
        (SignInTitle, Tr) => "Giriş yap",
        (SignInSub, En) => "One account for everything Dizey.",
        (SignInSub, Tr) => "Dizey'deki her şey için tek bir hesap.",
        (EmailLabel, En) => "Email",
        (EmailLabel, Tr) => "E-posta",
        (PasswordLabel, En) => "Password",
        (PasswordLabel, Tr) => "Parola",
        (SignInButton, En) => "Sign in",
        (SignInButton, Tr) => "Giriş yap",
        (ForgotIt, En) => "Forgot it?",
        (ForgotIt, Tr) => "Parolamı unuttum",
        (BrandFooter, En) => "im · Dizey SSO",
        (BrandFooter, Tr) => "im · Dizey SSO",
        (TotpTitle, En) => "Two-factor code",
        (TotpTitle, Tr) => "İki faktörlü kod",
        (TotpSub, En) => "The 6-digit code from your authenticator.",
        (TotpSub, Tr) => "Doğrulama uygulamasındaki 6 haneli kod.",
        (CodeLabel, En) => "Code",
        (CodeLabel, Tr) => "Kod",
        (VerifyButton, En) => "Verify",
        (VerifyButton, Tr) => "Doğrula",
        (InviteTitle, En) => "You're invited",
        (InviteTitle, Tr) => "Davetlisin",
        (InviteSub, En) => "Pick a name and a password. Next step sets up two-factor sign-in.",
        (InviteSub, Tr) => "Bir ad ve bir parola seç. Sonraki adımda iki faktörlü girişi kuracaksın.",
        (YourNameLabel, En) => "Your name",
        (YourNameLabel, Tr) => "Adın",
        (PasswordAgainLabel, En) => "Password again",
        (PasswordAgainLabel, Tr) => "Parola (tekrar)",
        (CreateAccountButton, En) => "Create account",
        (CreateAccountButton, Tr) => "Hesabı oluştur",
        (InviteDeadTitle, En) => "This link doesn't work",
        (InviteDeadTitle, Tr) => "Bu bağlantı çalışmıyor",
        (BackToSignIn, En) => "Back to sign in",
        (BackToSignIn, Tr) => "Girişe dön",
        (EnrollTitle, En) => "Set up two-factor",
        (EnrollTitle, Tr) => "İki faktörlüyü kur",
        (EnrollSub, En) => "Scan with your authenticator, then type the 6-digit code it shows.",
        (EnrollSub, Tr) => "Doğrulama uygulamanla tara, sonra gösterdiği 6 haneli kodu yaz.",
        (ConfirmAndSignIn, En) => "Confirm and sign in",
        (ConfirmAndSignIn, Tr) => "Onayla ve giriş yap",
        (ForgotTitle, En) => "Forgot it?",
        (ForgotTitle, Tr) => "Parolamı unuttum",
        (ForgotSub, En) => {
            "Your address gets a reset link, good for one password change. A fresh ask retires the last link."
        }
        (ForgotSub, Tr) => {
            "Adresine, tek bir parola değişikliği için geçerli bir sıfırlama bağlantısı gelir. Yeni bir istek, önceki bağlantıyı geçersiz kılar."
        }
        (ForgotSentNote, En) => "If that address has an account, a link is on its way.",
        (ForgotSentNote, Tr) => "Adres bir hesaba aitse sıfırlama bağlantısı yolda.",
        (SendLinkButton, En) => "Send the link",
        (SendLinkButton, Tr) => "Bağlantıyı gönder",
        (BackToSignInDash, En) => "Back to sign-in",
        (BackToSignInDash, Tr) => "Girişe dön",
        (ResetTitle, En) => "A fresh password",
        (ResetTitle, Tr) => "Yeni bir parola",
        (ResetSub, En) => "The change signs every device out, this one included.",
        (ResetSub, Tr) => "Bu değişiklik, bu dahil tüm cihazlardaki oturumları kapatır.",
        (NewPasswordAgainLabel, En) => "New password, again",
        (NewPasswordAgainLabel, Tr) => "Yeni parola (tekrar)",
        (TitleSignIn, En) => "Sign in · im",
        (TitleSignIn, Tr) => "Giriş · im",
        (TitleTotp, En) => "Two-factor · im",
        (TitleTotp, Tr) => "İki faktörlü · im",
        (TitleInvited, En) => "You're invited · im",
        (TitleInvited, Tr) => "Davetlisin · im",
        (TitleEnroll, En) => "Two-factor setup · im",
        (TitleEnroll, Tr) => "İki faktörlü kurulum · im",
        (TitleForgot, En) => "Forgot it? · im",
        (TitleForgot, Tr) => "Parolamı unuttum · im",
        (TitleReset, En) => "A fresh password · im",
        (TitleReset, Tr) => "Yeni parola · im",
        (TitleAdmin, En) => "Admin · im",
        (TitleAdmin, Tr) => "Yönetici · im",

        (TwoFaOn, En) => "2FA on",
        (TwoFaOn, Tr) => "2FA açık",
        (TwoFaOff, En) => "2FA off",
        (TwoFaOff, Tr) => "2FA kapalı",
        (AdminChip, En) => "Admin",
        (AdminChip, Tr) => "Yönetici",
        (MemberSinceLabel, En) => "Member since",
        (MemberSinceLabel, Tr) => "Üyelik başlangıcı",
        (PublicProfileLink, En) => "Public profile",
        (PublicProfileLink, Tr) => "Herkese açık profil",
        (EditProfileLink, En) => "Edit profile",
        (EditProfileLink, Tr) => "Profili düzenle",
        (StatSignIns, En) => "Sign-ins",
        (StatSignIns, Tr) => "Girişler",
        (StatActiveSessions, En) => "Active sessions",
        (StatActiveSessions, Tr) => "Aktif oturumlar",
        (StatConnectedApps, En) => "Connected apps",
        (StatConnectedApps, Tr) => "Bağlı uygulamalar",
        (SessionsTitle, En) => "Sessions",
        (SessionsTitle, Tr) => "Oturumlar",
        (SignOutEverywhere, En) => "Sign out everywhere",
        (SignOutEverywhere, Tr) => "Her yerde oturumu kapat",
        (AdminPanelLink, En) => "Admin panel",
        (AdminPanelLink, Tr) => "Yönetici paneli",
        (ViewPhotoAria, En) => "View photo",
        (ViewPhotoAria, Tr) => "Fotoğrafı görüntüle",
        (ThisSessionChip, En) => "This session",
        (ThisSessionChip, Tr) => "Bu oturum",
        (UnknownDevice, En) => "Unknown device",
        (UnknownDevice, Tr) => "Bilinmeyen cihaz",
        (DeviceLabel, En) => "Device",
        (DeviceLabel, Tr) => "Cihaz",
        (AddressLabel, En) => "Address",
        (AddressLabel, Tr) => "Adres",
        (SignedInLabel, En) => "Signed in",
        (SignedInLabel, Tr) => "Giriş",
        (LastSeenLabel, En) => "Last seen",
        (LastSeenLabel, Tr) => "Son görülme",
        (ExpiresLabel, En) => "Expires",
        (ExpiresLabel, Tr) => "Bitiş",
        (SignOutButton, En) => "Sign out",
        (SignOutButton, Tr) => "Oturumu kapat",
        (RevokeButton, En) => "Revoke",
        (RevokeButton, Tr) => "İptal et",

        (NavAccount, En) => "Account",
        (NavAccount, Tr) => "Hesap",
        (NavUsers, En) => "Users",
        (NavUsers, Tr) => "Kullanıcılar",
        (NavMail, En) => "Mail",
        (NavMail, Tr) => "Posta",
        (NavSettings, En) => "Settings",
        (NavSettings, Tr) => "Ayarlar",
        (NavLogs, En) => "Logs",
        (NavLogs, Tr) => "Kayıtlar",
        (OkInvited, En) => "Invite created.",
        (OkInvited, Tr) => "Davet oluşturuldu.",
        (OkRevoked, En) => "Sessions revoked — every device is signed out.",
        (OkRevoked, Tr) => "Oturumlar kapatıldı — her cihazın oturumu kapatıldı.",
        (OkDisabled, En) => "Account disabled.",
        (OkDisabled, Tr) => "Hesap devre dışı bırakıldı.",
        (OkEnabled, En) => "Account enabled.",
        (OkEnabled, Tr) => "Hesap etkinleştirildi.",
        (OkSmtpSaved, En) => "Mail settings saved.",
        (OkSmtpSaved, Tr) => "Posta ayarları kaydedildi.",
        (OkSmtpTest, En) => "Test mail sent.",
        (OkSmtpTest, Tr) => "Test postası gönderildi.",
        (OkPasswordChanged, En) => "Password changed — every other device is signed out.",
        (OkPasswordChanged, Tr) => "Parola değişti — diğer tüm cihazların oturumu kapatıldı.",
        (OkUninvited, En) => "Invite invalidated — the link is dead.",
        (OkUninvited, Tr) => "Davet geçersiz kılındı — bağlantı artık ölü.",
        (OkDeleted, En) => "Account deleted.",
        (OkDeleted, Tr) => "Hesap silindi.",
        (OkSettingsSaved, En) => "Settings saved.",
        (OkSettingsSaved, Tr) => "Ayarlar kaydedildi.",

        (AccountTitle, En) => "Account",
        (AccountTitle, Tr) => "Hesap",
        (SignedInAs, En) => "Signed in as",
        (SignedInAs, Tr) => "Giriş yapılan hesap",
        (TwoFactorOnNote, En) => "two-factor is on",
        (TwoFactorOnNote, Tr) => "iki faktörlü doğrulama açık",
        (TwoFactorOffNote, En) => "two-factor is NOT on — sign out and back in to set it up",
        (TwoFactorOffNote, Tr) => "iki faktörlü doğrulama KAPALI — kurmak için oturumu kapatıp tekrar aç",
        (AccountPasswordNote, En) => "Changing it signs every other device out — this one stays.",
        (AccountPasswordNote, Tr) => "Değiştirince diğer tüm cihazların oturumu kapanır — bu cihaz açık kalır.",
        (AdminSessionsEmpty, En) => "No active sessions",
        (AdminSessionsEmpty, Tr) => "Aktif oturum yok",

        (FlagAdmin, En) => "admin",
        (FlagAdmin, Tr) => "yönetici",
        (FlagDisabled, En) => "disabled",
        (FlagDisabled, Tr) => "devre dışı",
        (FlagNo2fa, En) => "no 2fa",
        (FlagNo2fa, Tr) => "2FA yok",
        (FlagInvited, En) => "invited",
        (FlagInvited, Tr) => "davet edildi",
        (YouWord, En) => "you",
        (YouWord, Tr) => "sen",
        (EnableWord, En) => "Enable",
        (EnableWord, Tr) => "Etkinleştir",
        (DisableWord, En) => "Disable",
        (DisableWord, Tr) => "Devre dışı bırak",
        (DeleteWord, En) => "Delete",
        (DeleteWord, Tr) => "Sil",
        (ConfirmEnable, En) => "Confirm enable",
        (ConfirmEnable, Tr) => "Etkinleştirmeyi onayla",
        (ConfirmDisable, En) => "Confirm disable",
        (ConfirmDisable, Tr) => "Devre dışı bırakmayı onayla",
        (ConfirmDelete, En) => "Confirm delete",
        (ConfirmDelete, Tr) => "Silmeyi onayla",
        (EnableCost, En) => "They can sign in again.",
        (EnableCost, Tr) => "Tekrar giriş yapabilir.",
        (DisableCost, En) => "They cannot sign in, and every live session ends.",
        (DisableCost, Tr) => "Giriş yapamaz ve tüm aktif oturumları sona erer.",
        (DeleteCost, En) => {
            "The account, its sessions and every app token go with it. The address can be invited again, as somebody new."
        }
        (DeleteCost, Tr) => {
            "Hesap, oturumları ve tüm uygulama jetonlarıyla birlikte silinir. Adres, yeni biri olarak tekrar davet edilebilir."
        }
        (InvalidateButton, En) => "Invalidate",
        (InvalidateButton, Tr) => "Geçersiz kıl",
        (InviteLinkNote, En) => "The link exists once. It is shown once:",
        (InviteLinkNote, Tr) => "Bağlantı bir kez oluşturulur. Bir kez gösterilir:",
        (PeopleTitle, En) => "People",
        (PeopleTitle, Tr) => "Kişiler",
        (EmailCol, En) => "Email",
        (EmailCol, Tr) => "E-posta",
        (NameCol, En) => "Name",
        (NameCol, Tr) => "Ad",
        (RoleMember, En) => "member",
        (RoleMember, Tr) => "üye",
        (RoleAdmin, En) => "admin",
        (RoleAdmin, Tr) => "yönetici",
        (InviteButton, En) => "Invite",
        (InviteButton, Tr) => "Davet et",

        (SettingsTitle, En) => "Settings",
        (SettingsTitle, Tr) => "Ayarlar",
        (SettingsSub, En) => {
            "The rules identity lives by. They apply from the next invite, sign-in or link — nothing already minted is rewritten."
        }
        (SettingsSub, Tr) => {
            "Kimliğin kuralları burada. Bir sonraki davet, giriş ya da bağlantıdan itibaren geçerlidir — önceden oluşturulmuş hiçbir şey yeniden yazılmaz."
        }
        (InviteDaysLabel, En) => "Invite link, days",
        (InviteDaysLabel, Tr) => "Davet bağlantısı, gün",
        (SessionDaysLabel, En) => "Sign-in session, days",
        (SessionDaysLabel, Tr) => "Oturum süresi, gün",
        (PendingMinutesLabel, En) => "Second-factor window, minutes",
        (PendingMinutesLabel, Tr) => "İkinci faktör penceresi, dakika",
        (ResetMinutesLabel, En) => "Reset link, minutes",
        (ResetMinutesLabel, Tr) => "Sıfırlama bağlantısı, dakika",
        (LoginAttemptsLabel, En) => "Failed sign-ins per address per hour",
        (LoginAttemptsLabel, Tr) => "Adres başına saatlik başarısız giriş",
        (SaveButton, En) => "Save",
        (SaveButton, Tr) => "Kaydet",

        (MailTitle, En) => "Mail",
        (MailTitle, Tr) => "Posta",
        (ChipNotConfigured, En) => "not configured",
        (ChipNotConfigured, Tr) => "Yapılandırılmadı",
        (ChipUnchecked, En) => "unchecked",
        (ChipUnchecked, Tr) => "Denenmedi",
        (ChipRefused, En) => "refused",
        (ChipRefused, Tr) => "Reddedildi",
        (ChipConnectedWord, En) => "connected",
        (ChipConnectedWord, Tr) => "bağlı",
        (HostLabel, En) => "Host",
        (HostLabel, Tr) => "Sunucu",
        (PortLabel, En) => "Port",
        (PortLabel, Tr) => "Port",
        (UsernameLabel, En) => "Username",
        (UsernameLabel, Tr) => "Kullanıcı adı",
        (MailPasswordLabel, En) => "Password",
        (MailPasswordLabel, Tr) => "Parola",
        (FromNameLabel, En) => "From name",
        (FromNameLabel, Tr) => "Gönderen adı",
        (FromAddressLabel, En) => "From address",
        (FromAddressLabel, Tr) => "Gönderen adresi",
        (PasswordSetNote, En) => "password is set — fill to replace, leave empty to keep",
        (PasswordSetNote, Tr) => "parola kayıtlı — değiştirmek için doldur, kalsınsa boş bırak",
        (NoPasswordNote, En) => "no password set",
        (NoPasswordNote, Tr) => "parola kayıtlı değil",
        (CheckConnectionButton, En) => "Check connection",
        (CheckConnectionButton, Tr) => "Bağlantıyı dene",
        (SendTestMailButton, En) => "Send a test mail to myself",
        (SendTestMailButton, Tr) => "Kendime test postası gönder",
        (UncheckedNote, En) => {
            "Saved, but never checked — the check dials the server and stops before sending."
        }
        (UncheckedNote, Tr) => {
            "Kaydedildi ama hiç denetlenmedi — denetim sunucuyu arar ve göndermeden durur."
        }

        (LogsTitle, En) => "Logs",
        (LogsTitle, Tr) => "Kayıtlar",
        (LogsSub, En) => {
            "Everything identity did, newest first. Introspection is not logged — it runs per request and would drown the rest."
        }
        (LogsSub, Tr) => {
            "Kimliğin yaptığı her şey, yeniden eskiye. Yoklama kaydedilmez — istek başına çalışır ve gerisini boğardı."
        }
        (WhenCol, En) => "When",
        (WhenCol, Tr) => "Ne zaman",
        (WhatCol, En) => "What",
        (WhatCol, Tr) => "Ne",
        (WhoCol, En) => "Who",
        (WhoCol, Tr) => "Kim",
        (DetailCol, En) => "Detail",
        (DetailCol, Tr) => "Ayrıntı",

        (InviteMailSubject, En) => "You're invited",
        (InviteMailSubject, Tr) => "Davetlisin",
        (TestMailSubject, En) => "im mail test",
        (TestMailSubject, Tr) => "im posta denemesi",
        (TestMailBody, En) => "im can send mail from this sender.\n",
        (TestMailBody, Tr) => "im bu gönderen üzerinden posta gönderebiliyor.\n",

        // Preference phrases: iz-verbatim English/Turkish where iz has the
        // key; im's own sentence-case labels where the same key names an im
        // form today (Turkish follows iz's wording).
        (ThemeLabel, En) => "THEME",
        (ThemeLabel, Tr) => "TEMA",
        (UiLabel, En) => "INTERFACE",
        (UiLabel, Tr) => "ARAYÜZ",
        (LanguageLabel, En) => "LANGUAGE",
        (LanguageLabel, Tr) => "DİL",
        (LightOption, En) => "Light",
        (LightOption, Tr) => "Açık",
        (DarkOption, En) => "Dark",
        (DarkOption, Tr) => "Koyu",
        (InstrumentOption, En) => "Instrument",
        (InstrumentOption, Tr) => "Enstrüman",
        (LedgerOption, En) => "Ledger",
        (LedgerOption, Tr) => "Defter",
        (PreferencesLabel, En) => "Preferences",
        (PreferencesLabel, Tr) => "Tercihler",
        (ChangePassword, En) => "Change password",
        (ChangePassword, Tr) => "Parolayı değiştir",
        (CurrentPasswordLabel, En) => "Current password",
        (CurrentPasswordLabel, Tr) => "Mevcut parola",
        (NewPasswordLabel, En) => "New password",
        (NewPasswordLabel, Tr) => "Yeni parola",
        (Saved, En) => "Saved.",
        (Saved, Tr) => "Kaydedildi.",
        (PasswordSaved, En) => "Password changed. Your other devices were signed out.",
        (PasswordSaved, Tr) => "Parola değişti. Diğer cihazlarının oturumu kapatıldı.",
        (PWTooShort, En) => "At least 10 characters.",
        (PWTooShort, Tr) => "En az 10 karakter.",
        (PWLooksLikeYou, En) => "Not your address or your name.",
        (PWLooksLikeYou, Tr) => "Adresin ya da adın değil.",
        (PWIsCurrent, En) => "That's your current password.",
        (PWIsCurrent, Tr) => "Bu zaten mevcut parolan.",
        (PWCurrentWrong, En) => "The current password is wrong.",
        (PWCurrentWrong, Tr) => "Mevcut parola yanlış.",

        (Change, En) => "Change",
        (Change, Tr) => "Değiştir",
        (Remove, En) => "Remove",
        (Remove, Tr) => "Kaldır",
        (CancelUploadLabel, En) => "Cancel upload",
        (CancelUploadLabel, Tr) => "Yüklemeyi iptal et",
    }
}

/// The account section's "Signed in as … · …" line, in the admin's language.
/// `email_html` is already escaped; the mono span is markup, not prose.
pub fn account_sub(lang: Lang, email_html: &str, two_factor: &str) -> String {
    match lang {
        Lang::En => format!(
            "{} <span class=\"mono\">{email_html}</span> · {two_factor}.",
            t(lang, Key::SignedInAs)
        ),
        Lang::Tr => format!(
            "<span class=\"mono\">{email_html}</span> olarak giriş yapıldı · {two_factor}."
        ),
    }
}

/// A user row's "Sessions (N)" disclosure summary, in the viewer's language.
pub fn sessions_summary(lang: Lang, n: usize) -> String {
    match lang {
        Lang::En => format!("Sessions ({n})"),
        Lang::Tr => format!("Oturumlar ({n})"),
    }
}

/// A pending invite's "waiting · until <date>" cell, in the viewer's language.
pub fn waiting_label(lang: Lang, date: &str) -> String {
    match lang {
        Lang::En => format!("waiting · until {date}"),
        Lang::Tr => format!("{date} tarihine kadar bekleniyor"),
    }
}

/// The mail section's standing chip when the last probe passed.
pub fn connected_chip(lang: Lang, took_ms: u64) -> String {
    match lang {
        Lang::En => format!("{} · {took_ms} ms", t(lang, Key::ChipConnectedWord)),
        Lang::Tr => format!("{} · {took_ms} ms", t(lang, Key::ChipConnectedWord)),
    }
}

/// The mail section's standing line under a passing chip.
pub fn checked_note(lang: Lang, when: &str) -> String {
    match lang {
        Lang::En => format!("Checked {when} — TLS, hello, password: all accepted."),
        Lang::Tr => format!("{when} denetlendi — TLS, merhaba, parola: hepsi kabul edildi."),
    }
}

/// A row action's "Enable/Disable/Delete <email>?" title. `email_html` is
/// already escaped.
pub fn enable_title(lang: Lang, email_html: &str) -> String {
    match lang {
        Lang::En => format!("Enable {email_html}?"),
        Lang::Tr => format!("{email_html} etkinleştirilsin mi?"),
    }
}

/// See [`enable_title`].
pub fn disable_title(lang: Lang, email_html: &str) -> String {
    match lang {
        Lang::En => format!("Disable {email_html}?"),
        Lang::Tr => format!("{email_html} devre dışı bırakılsın mı?"),
    }
}

/// See [`enable_title`].
pub fn delete_title(lang: Lang, email_html: &str) -> String {
    match lang {
        Lang::En => format!("Delete {email_html}?"),
        Lang::Tr => format!("{email_html} silinsin mi?"),
    }
}

/// The mail section's lede: what the sender is for. The mono span is markup.
pub fn mail_sub(lang: Lang) -> String {
    match lang {
        Lang::En => "Invites go out through this sender. The password is sealed under <span class=\"mono\">im.key</span>; without a sender, invite links are shown here instead of mailed.".to_string(),
        Lang::Tr => "Davetler bu gönderen üzerinden gider. Parola <span class=\"mono\">im.key</span> altında mühürlüdür; gönderen yoksa davet bağlantıları postalanmak yerine burada gösterilir.".to_string(),
    }
}

/// The invite mail: the link is the whole payload. The invitee has no
/// account and no preference yet, so this stays English — iz does the same.
pub fn invite_mail(link: &str, days: i64) -> (String, String) {
    (
        t(Lang::En, Key::InviteMailSubject).to_string(),
        format!("You've been invited. This link is yours for {days} days:\n\n{link}\n"),
    )
}

/// The reset mail: the link is the whole payload, in the account's language
/// — mirroring iz's `reset_mail` TR/EN branch.
pub fn reset_mail(lang: Lang, link: &str, minutes: i64) -> (String, String) {
    match lang {
        Lang::En => (
            "Reset your password".to_string(),
            format!(
                "A password reset was asked for this address. The link is yours for {minutes} minutes:\n\n{link}\n\nIf that wasn't you, this mail changes nothing.\n"
            ),
        ),
        Lang::Tr => (
            "im parolanı sıfırla".to_string(),
            format!(
                "Bu adres için bir im parola sıfırlaması istendi. Bağlantı {minutes} dakika boyunca senin:\n\n{link}\n\nBu sen değilsen, bu posta hiçbir şeyi değiştirmez.\n"
            ),
        ),
    }
}
