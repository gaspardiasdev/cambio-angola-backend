const mongoose = require("mongoose");
const { Schema } = mongoose;

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isPremium: {
      type: Boolean,
      default: false,
    },
    phoneNumber: {
      type: String, // Adiciona este novo campo
      trim: true,
    },
    dateCreated: {
      type: Date,
      default: Date.now,
    },
    lastLogin: {
      type: Date,
    },
    premiumUpgradeDate: {
      type: Date,
      default: null,
    },
    premiumExpiryDate: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("User", userSchema);
