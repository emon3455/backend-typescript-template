import httpStatus from "http-status-codes";
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";
import AppError from "../../errorHelpers/AppError";
import { createNewAccessTokenWithRefreshToken } from "../../utils/userTokens";
import { User } from "../user/user.model";
import { IAuthProvider } from "../user/user.interface";
import { hashPassword, verifyPassword } from "../../utils/hash";
import { OTPService } from "../otp/otp.service";
import { envVars } from "../../config/env";

const getNewAccessToken = async (refreshToken: string) => {
  const newAccessToken = await createNewAccessTokenWithRefreshToken(
    refreshToken
  );

  return {
    accessToken: newAccessToken,
  };
};

const forgotPassword = async (email: string) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(httpStatus.BAD_REQUEST, "User does not exist");
  if (!user.isVerified) throw new AppError(httpStatus.BAD_REQUEST, "User is not verified");
  if (user.isDeleted) throw new AppError(httpStatus.BAD_REQUEST, "User is deleted");

  await OTPService.sendOTP(email, "reset_password");
  return true;
};

const verifyResetOtpAndIssueToken = async (email: string, otpCode: string) => {
  await OTPService.verifyOTP(email, otpCode, "reset_password");

  const user = await User.findOne({ email });
  if (!user) throw new AppError(httpStatus.NOT_FOUND, "User not found");

  const payload = { userId: String(user._id), email: user.email, purpose: "reset_password" };
  const resetToken = jwt.sign(payload, envVars.JWT_RESET_SECRET, { expiresIn: envVars.JWT_RESET_EXPIRES }as SignOptions);

  return resetToken;
};

const resetPassword = async (token: string, newPassword: string) => {
  let decoded: JwtPayload;
  try {
    decoded = jwt.verify(String(token).trim(), envVars.JWT_RESET_SECRET) as JwtPayload;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    if (err?.name === "TokenExpiredError") {
      throw new AppError(httpStatus.UNAUTHORIZED, "Reset link expired");
    }
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid reset token");
  }

  // Optional: enforce purpose in token
  if (decoded.purpose !== "reset_password") {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid reset token purpose");
  }

  const user = await User.findById(decoded.userId);
  if (!user) throw new AppError(httpStatus.BAD_REQUEST, "User does not exist");
  if (user.isDeleted) throw new AppError(httpStatus.BAD_REQUEST, "User is deleted");

  user.password = await hashPassword(newPassword);
  await user.save();

  return true;
};

const setPassword = async (userId: string, plainPassword: string) => {
  const user = await User.findById(userId);

  if (!user) throw new AppError(404, "User not found");
  if (
    user.password &&
    user.auths.some((providerObject) => providerObject.provider === "google")
  ) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "You have already set your password. Now you can change the password from your profile password update"
    );
  }

  const hashedPassword = await hashPassword(plainPassword);

  const credentialProvider: IAuthProvider = {
    provider: "credentials",
    providerId: user.email,
  };

  const auths: IAuthProvider[] = [...user.auths, credentialProvider];

  user.password = hashedPassword;
  user.auths = auths;

  await user.save();
};

const changePassword = async (
  oldPassword: string,
  newPassword: string,
  decodedToken: JwtPayload
) => {
  const user = await User.findById(decodedToken.userId);

  if (!user || !user.password) throw new AppError(404, "User not found");

  const isOldPasswordValid = await verifyPassword(oldPassword, user.password);

  if (!isOldPasswordValid) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Old Password does not match");
  }

  user.password = await hashPassword(newPassword);

  await user.save();
};


export const AuthServices = {
  getNewAccessToken,
  resetPassword,
  changePassword,
  setPassword,
  forgotPassword,
  verifyResetOtpAndIssueToken
};
