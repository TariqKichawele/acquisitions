export const cookies = {
  getOptions: () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 15 * 60 * 1000,
    sameSite: 'strict',
  }),
  set: (res, name, value, options) => {
    res.cookie(name, value, { ...cookies.getOptions(), ...options });
  },
  get: (req, name) => {
    return req.cookies[name];
  },
  clear: (res, name, options) => {
    res.clearCookie(name, { ...cookies.getOptions(), ...options });
  },
};