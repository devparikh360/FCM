// src/firebase.js
import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

// Your Firebase config object will come here
const firebaseConfig = {
   apiKey: "AIzaSyCINt-MuVJa2xslHA2GvPuZ3LM8sRMNL90",
  authDomain: "fcm-app-40684.firebaseapp.com",
  projectId: "fcm-app-40684",
  storageBucket: "fcm-app-40684.firebasestorage.app",
  messagingSenderId: "346292955526",
  appId: "1:346292955526:web:b0a75b48cd7339ef6f2407",
  measurementId: "G-5L7SNB506T"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Auth + Provider
const auth = getAuth(app);
const provider = new GoogleAuthProvider();

// Firestore Database
const db = getFirestore(app);

export { auth, provider, db };