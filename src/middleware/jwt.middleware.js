const jwt = require("jsonwebtoken");
const User = require("../models/user");

const validarJWT = async (req, res, next) => {
  const token = req.header("x-token");

  if (!token) {
    return res.status(401).json({
      ok: false,
      msg: "No hay token en la peticion",
      data: {},
    });
  }

  try {
    const { id } = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(id);

    if (!user) {
      return res.status(401).json({
        ok: false,
        msg: "token no valido",
        data: {},
      });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({
      ok: false,
      msg: "token no valido",
      data: {},
    });
  }
};

module.exports = {
  validarJWT,
};
