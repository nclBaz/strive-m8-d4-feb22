import mongoose from "mongoose"
import bcrypt from "bcrypt"

const { Schema, model } = mongoose

const UserSchema = new Schema(
  {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["User", "Admin"], default: "User" },
    refreshToken: { type: String },
  },
  {
    timestamps: true,
  }
)

UserSchema.pre("save", async function (next) {
  // BEFORE saving the user in db, execute a function (in this case hash the password)
  // I am NOT using arrow functions here because of "this"

  const currentUser = this // "this" here represents the current user I am trying to save in db
  const plainPW = this.password

  if (currentUser.isModified("password")) {
    // only if the user is modifying the password I will use some CPU cycles to calculate the hash, otherwise they would be just wasetd
    const hash = await bcrypt.hash(plainPW, 11)
    currentUser.password = hash
  }

  next()
})

UserSchema.methods.toJSON = function () {
  // this toJSON method will be used EVERY TIME Express does a res.send(user/s)
  // we could override the behaviour of this method to remove the password from the user and then return him/her

  const userDocument = this
  const userObject = userDocument.toObject()

  delete userObject.password
  delete userObject.__v
  delete userObject.refreshToken

  return userObject
}

// Custom Mongoose method --> Check Credentials

UserSchema.static("checkCredentials", async function (email, plainPW) {
  // This is a custom method that given email and password will return the User if credentials are fine or null if they are not

  // 1. Find the user by email
  const user = await this.findOne({ email }) // "this" here refers to the UsersModel

  if (user) {
    // 2. If the email is found --> compare plainPW with the hashed one
    const isMatch = await bcrypt.compare(plainPW, user.password)
    if (isMatch) {
      // 3. If they do match --> return the user
      return user
    } else {
      return null
    }
  } else {
    // 4. In case of either email not found or password not correct --> return null
    return null
  }
})

export default model("User", UserSchema)
