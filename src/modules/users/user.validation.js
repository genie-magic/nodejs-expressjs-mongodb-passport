import Joi from 'joi';

export const passwordReg = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/;

export default {
  signup: {
    email: Joi.string().email().required(),
    password: Joi.string().regex(passwordReg).required(),
    userName: Joi.string().required(),
  }
}
