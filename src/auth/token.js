import createHttpError from "http-errors"
import { verifyAccessToken } from "./tools.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  // 1. Check if authorization header is in the request, if it is not --> 401
  console.log("COOKIES: ", req.cookies)
  if (!req.cookies.accessToken) {
    next(createHttpError(401, "Please provide access token in cookies!"))
  } else {
    try {
      // 2. Extract token from cookies
      const token = req.cookies.accessToken

      // 3. Verify token (check the expiration date and check the signature integrity), if everything is fine we should get back the payload ({_id, role})
      const payload = await verifyAccessToken(token)

      // 4. If token is ok --> next

      req.user = {
        _id: payload._id,
        role: payload.role,
      }

      next()
    } catch (error) {
      // 5. If the token is not ok --> jsonwebtoken library should throw some errors, so we gonna catch'em and --> 401
      console.log(error)
      next(createHttpError(401, "Token not valid!"))
    }
  }
}
