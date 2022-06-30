import createHttpError from "http-errors"
import jwt from "jsonwebtoken"
import UsersModel from "../api/users/model.js"

export const authenticateUser = async user => {
  // 1. Given the user, it generates two tokens (accessToken & refreshToken)
  const accessToken = await generateAccessToken({ _id: user._id, role: user.role })
  const refreshToken = await generateRefreshToken({ _id: user._id })

  // 2. Refresh Token should be saved in db
  user.refreshToken = refreshToken
  await user.save() // remember that user is a MONGOOSE DOCUMENT, therefore it has some special powers like .save() method

  // 3. Return the two tokens
  return { accessToken, refreshToken }
}

export const verifyRefreshTokenAndGenerateNewTokens = async currentRefreshToken => {
  try {
    // 1. Check expiration date and integrity of the refresh token, we gonna catch potential errors
    const payload = await verifyRefreshToken(currentRefreshToken)

    // 2. If the token is valid, we shall check if it matches to the one we have in db
    const user = await UsersModel.findById(payload._id)
    if (!user) throw createHttpError(404, `User with id ${payload._id} not found!`)

    if (user.refreshToken && user.refreshToken === currentRefreshToken) {
      // 3. If everything is fine --> generate new tokens and return them
      const { accessToken, refreshToken } = await authenticateUser(user)
      return { accessToken, refreshToken }
    } else {
      throw createHttpError(401, "Refresh token not valid!")
    }
  } catch (error) {
    // 4. In case of troubles --> catch the error and send 401
    throw createHttpError(401, "Refresh token not valid!")
  }
}

const generateAccessToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15 min" }, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  )

export const verifyAccessToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
      if (err) rej(err)
      else res(payload)
    })
  )

const generateRefreshToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: "1 week" }, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  )

const verifyRefreshToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.JWT_REFRESH_SECRET, (err, payload) => {
      if (err) rej(err)
      else res(payload)
    })
  )
