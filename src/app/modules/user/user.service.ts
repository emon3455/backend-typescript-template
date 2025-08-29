import httpStatus from "http-status-codes";
import { JwtPayload } from "jsonwebtoken";
import AppError from "../../errorHelpers/AppError";
import { IAuthProvider, IUser, Role } from "./user.interface";
import { User } from "./user.model";
import { hashPassword } from "../../utils/hash";
import { QueryBuilder } from "../../utils/QueryBuilder";
import { IGenericResponse } from "../../interfaces/common";

const getMe = async (userId: string) => {
  const user = await User.findById(userId).select("-password");
  return {
    data: user,
  };
};

const createUser = async (payload: Partial<IUser>) => {
  const { email, password, ...rest } = payload;

  const isUserExist = await User.findOne({ email });

  if (isUserExist) {
    throw new AppError(httpStatus.BAD_REQUEST, "User Already Exist");
  }

  const hashedPassword = await hashPassword(password as string);

  const authProvider: IAuthProvider = {
    provider: "credentials",
    providerId: email as string,
  };

  const user = await User.create({
    email,
    password: hashedPassword,
    auths: [authProvider],
    ...rest,
  });

  return user;
};

const updateUser = async (
  userId: string,
  payload: Partial<IUser>,
  decodedToken: JwtPayload
) => {
  const ifUserExist = await User.findById(userId);

  if (!ifUserExist) {
    throw new AppError(httpStatus.NOT_FOUND, "User Not Found");
  }

  if (payload.role) {
    if (decodedToken.role === Role.USER || decodedToken.role === Role.GUIDE) {
      throw new AppError(httpStatus.FORBIDDEN, "You are not authorized");
    }

    if (payload.role === Role.SUPER_ADMIN && decodedToken.role === Role.ADMIN) {
      throw new AppError(httpStatus.FORBIDDEN, "You are not authorized");
    }
  }

  if (payload.isActive || payload.isDeleted || payload.isVerified) {
    if (decodedToken.role === Role.USER || decodedToken.role === Role.GUIDE) {
      throw new AppError(httpStatus.FORBIDDEN, "You are not authorized");
    }
  }

  if (payload.password) {
    payload.password = await hashPassword(
      payload.password as string);
  }

  const newUpdatedUser = await User.findByIdAndUpdate(userId, payload, {
    new: true,
    runValidators: true,
  });

  return newUpdatedUser;
};

const getAllUsers = async (
  query: Record<string, string>
): Promise<IGenericResponse<IUser[]>> => {
  const modifiedQuery = { ...query };

  const baseQuery = User.find();

  const queryBuilder = new QueryBuilder(baseQuery, modifiedQuery)
    .filter()
    .search(["name", "email", "phone"])
    .sort()
    .fields()
    .paginate();

  const allUsers = await queryBuilder.build();
  const meta = await queryBuilder.getMeta();

  return {
    data: allUsers,
    meta,
  };
};

const updateMe = async (
  payload: Partial<IUser>,
  decodedToken: JwtPayload
) => {
  
  const ifUserExist = await User.findById(decodedToken?.userId);

  if (!ifUserExist) {
    throw new AppError(httpStatus.NOT_FOUND, "User Not Found");
  }

  if (payload.password) {
    payload.password = await hashPassword(payload.password as string);
  }

  const newUpdatedUser = await User.findByIdAndUpdate(decodedToken?.userId, payload, {
    new: true,
    runValidators: true,
  });

  return newUpdatedUser;
};

export const UserServices = {
  createUser,
  getAllUsers,
  updateUser,
  getMe,
  updateMe
};
