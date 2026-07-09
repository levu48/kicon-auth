/**
 * Authentication-strength markers, emitted as the id_token `acr`/`amr` claims so
 * resource servers can tell how strongly a session was authenticated.
 */
export const ACR_PWD = 'urn:kicon:loa1'; // password only
export const ACR_MFA = 'urn:kicon:loa2'; // password + second factor

export const AMR_PWD = ['pwd'];
export const AMR_MFA = ['pwd', 'otp'];
