import createHttpError from "http-errors"
import atob from "atob"
import UsersModel from "../api/users/model.js"

export const basicAuthMiddleware = async (req, res, next) => {
  // Here we are receiving something like --> Authorization: "Basic QmV0dHllNEBnbWFpbC5jb206MTIzNA=="
  // 1. Check if authorization header is provided, if it is not --> trigger an error (401)
  if (!req.headers.authorization) {
    next(createHttpError(401, "Please provide credentials in Authorization header!"))
  } else {
    // 2. If we have received authorization header, we should extract the credentials out of it (credentials are base64 encoded, therefore we should decode them)
    const base64Credentials = req.headers.authorization.split(" ")[1]
    const [email, password] = atob(base64Credentials).split(":") // --> Bettye4@gmail.com:1234

    // 3. Once we obtain the credentials, it's time to find the user in the db by email and then compare received password with the hashed one
    const user = await UsersModel.checkCredentials(email, password)

    if (user) {
      // 4.a If credentials are ok, we can proceed to what is next (another middleware or route handler)
      req.user = user
      next()
    } else {
      // 4.b If credentials are NOT ok (email not found or password not correct) --> trigger an error (401)
      next(createHttpError(401, "Credentials are wrong!"))
    }
  }
}
