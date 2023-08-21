import React, { useState } from 'react';
import { object, string, TypeOf } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, FormProvider, SubmitHandler } from "react-hook-form";
import { useEffect } from "react";
import FormInput from "../components/FormInput";
import { LoadingButton } from "../components/LoadingButton";
import { toast } from "react-toastify";
import { Link, useNavigate } from "react-router-dom";
import { authApi } from "../api/authApi";
import useStore from "../store";
import { GenericResponse } from "../api/types";

const passwordStrength = (password:string) => {
  // Define the regular expressions for different password strength criteria
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/;
  const mediumRegex = /^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d]{8,32}$/;

  if (strongRegex.test(password)) {
    return 'strong';
  } else if (mediumRegex.test(password)) {
    return 'medium';
  } else {
    return 'weak';
  }
};

const registerSchema = object({
  name: string().min(1, 'Full name is required').max(100),
  email: string().min(1, 'Email address is required').email('Email Address is invalid'),
  password: string()
    .min(1, 'Password is required')
    .min(8, 'Password must be more than 8 characters')
    .max(32, 'Password must be less than 32 characters'),
  passwordConfirm: string().min(1, 'Please confirm your password'),
}).refine(
  (data) => data.password === data.passwordConfirm,
  {
    path: ['passwordConfirm'],
    message: 'Passwords do not match',
  }
).refine((data) => {
  const strength = passwordStrength(data.password);
  return strength === 'strong' || strength === 'medium';
}, {
  path: ['password'],
  message: 'Password is too weak. It should be at least medium strength.',
});

export type RegisterInput = TypeOf<typeof registerSchema>;

const RegisterPage = () => {
  const navigate = useNavigate();
  const store = useStore();
  const [showPassword, setShowPassword] = useState(false); // Added state for showing/hiding password

  const methods = useForm<RegisterInput>({
    resolver: zodResolver(registerSchema),
  });

  const {
    reset,
    handleSubmit,
    formState: { isSubmitSuccessful },
  } = methods;

  useEffect(() => {
    if (isSubmitSuccessful) {
      reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSubmitSuccessful]);

  const registerUser = async (data: RegisterInput) => {
    try {
      store.setRequestLoading(true);
      const response = await authApi.post<GenericResponse>(
        "auth/register",
        data
      );
      toast.success(response.data.message, {
        position: "top-right",
      });
      store.setRequestLoading(false);
      navigate("/login");
    } catch (error: any) {
      store.setRequestLoading(false);
      const resMessage =
        (error.response &&
          error.response.data &&
          error.response.data.message) ||
        error.response.data.detail ||
        error.message ||
        error.toString();
      toast.error(resMessage, {
        position: "top-right",
      });
    }
  };

  const onSubmitHandler: SubmitHandler<RegisterInput> = (values) => {
    registerUser(values);
  };

  return (
    <section className="py-8 bg-ct-blue-600 min-h-screen grid place-items-center">
      <div className="w-full">
        <h1 className="text-4xl xl:text-6xl text-center font-[600] text-ct-yellow-600 mb-4">
          Welcome to password Strength Checker and Authentication !
        </h1>
        <h2 className="text-lg text-center mb-4 text-ct-dark-200">
          Sign Up To Get Started!
        </h2>
        <FormProvider {...methods}>
          <form
            onSubmit={handleSubmit(onSubmitHandler)}
            className="max-w-md w-full mx-auto overflow-hidden shadow-lg bg-ct-dark-200 rounded-2xl p-8 space-y-5"
          >
            <FormInput label="Full Name" name="name" />
            <FormInput label="Email" name="email" type="email" />
            <div className="relative">
              <FormInput
                label="Password"
                name="password"
                type={showPassword ? 'text' : 'password'}
              />
              <button
                type="button"
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-ct-blue-600 hover:text-ct-blue-800 focus:outline-none"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  marginTop:"1rem"
                }}
              >
                {showPassword ? 'Hide' : 'Show'}
                
              </button>
            </div>
            <FormInput
              label="Confirm Password"
              name="passwordConfirm"
              type={showPassword ? 'text' : 'password'}
            />
            <span className="block">
              Already have an account?{" "}
              <Link to="/login" className="text-ct-blue-600">
                Login Here
              </Link>
            </span>
            <LoadingButton
              loading={store.requestLoading}
              textColor="text-ct-blue-600"
            >
              Sign Up
            </LoadingButton>
          </form>
        </FormProvider>
      </div>
    </section>
  );
};

export default RegisterPage;
