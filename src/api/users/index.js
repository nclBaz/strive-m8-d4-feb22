import express from "express"
import createError from "http-errors"
import passport from "passport"
import { adminOnlyMiddleware } from "../../auth/admin.js"
import { basicAuthMiddleware } from "../../auth/basic.js"
import { JWTAuthMiddleware } from "../../auth/token.js"
import { authenticateUser, verifyRefreshTokenAndGenerateNewTokens } from "../../auth/tools.js"
import UsersModel from "./model.js"

const usersRouter = express.Router()

usersRouter.get("/googleLogin", passport.authenticate("google", { scope: ["profile", "email"] })) // The purpose of this endpoint is to redirect users to Google Consent Screen
usersRouter.get("/googleRedirect", passport.authenticate("google", { session: false }), (req, res, next) => {
  // The purpose of this endpoint is to receive a response from Google, execute the google callback function, then send a response to the client
  try {
    const { accessToken, refreshToken } = req.user // passportNext is adding accessToken and refreshToken to req.user

    // as an alternative to url search params we could use cookies
    // res.redirect(`${process.env.FE_URL}/users?accessToken=${accessToken}&refreshToken=${refreshToken}`)
    res.cookie("accessToken", accessToken, { httpOnly: true, secure: process.env.NODE_ENV === "production" ? true : false, sameSite: "none" })
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === "production" ? true : false, sameSite: "none" })
    res.redirect(`${process.env.FE_URL}/users`)
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/", async (req, res, next) => {
  try {
    const newUser = new UsersModel(req.body)
    const { _id } = await newUser.save()
    res.status(201).send({ _id })
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const users = await UsersModel.find({})
    res.send(users)
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const me = await UsersModel.findById(req.user._id)
    res.send(me)
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const modifiedUser = await UsersModel.findByIdAndUpdate(req.user._id, req.body, { new: true })
    res.send(modifiedUser)
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    await UsersModel.findByIdAndDelete(req.user._id)
    res.status(204).send()
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findById(req.params.userId)
    if (user) {
      res.send(user)
    } else {
      next(createError(404, `User with id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const updatedUser = await UsersModel.findByIdAndUpdate(req.params.userId, req.body, { new: true, runValidators: true })
    if (updatedUser) {
      res.send(updatedUser)
    } else {
      next(createError(404, `User with id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const deletedUser = await UsersModel.findByIdAndDelete(req.params.userId)
    if (deletedUser) {
      res.status(204).send()
    } else {
      next(createError(404, `User with id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/login", async (req, res, next) => {
  try {
    // 1. Obtain credentials from req.body
    const { email, password } = req.body

    // 2. Verify credentials
    const user = await UsersModel.checkCredentials(email, password)

    if (user) {
      // 3. If credentials are fine --> generate an access token & refresh token (JWT) then send them as a response
      const { accessToken, refreshToken } = await authenticateUser(user)
      res.cookie("accessToken", accessToken, { httpOnly: true, secure: process.env.NODE_ENV === "production" ? true : false, sameSite: "none" })
      res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === "production" ? true : false, sameSite: "none" })
      res.send()
    } else {
      // 4. If credentials are not ok --> throw an error (401)
      next(createError(401, "Credentials are not ok!"))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/refreshTokens", async (req, res, next) => {
  try {
    // 1. Obtain refreshToken from req.body
    const currentRefreshToken = req.cookies.refreshToken

    // 2. Check the validity of that token (check if it is not expired, check if it hasn'been compromised, check if it is the same as the one we have in db)
    // 3. If everything is fine --> generate a new pair of tokens (accessToken2 & refreshToken2)
    const { accessToken, refreshToken } = await verifyRefreshTokenAndGenerateNewTokens(currentRefreshToken)
    // 4. Send them back as a response
    res.cookie("accessToken", accessToken, { httpOnly: true, secure: process.env.NODE_ENV === "production" ? true : false, sameSite: "none" })
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === "production" ? true : false, sameSite: "none" })
    res.send()
  } catch (error) {
    next(error)
  }
})

export default usersRouter
