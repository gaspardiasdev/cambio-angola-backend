// models/userModel.js - Updated version
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: function() {
        // Password is only required if not using Google auth
        return !this.googleId;
      },
    },
    // Google OAuth fields
    googleId: {
      type: String,
      sparse: true, // Allows null values while maintaining uniqueness
    },
    name: {
      type: String,
      trim: true,
    },
    picture: {
      type: String, // Google profile picture URL
    },
    authProvider: {
      type: String,
      enum: ['local', 'google'],
      default: 'local'
    },
    isEmailVerified: {
      type: Boolean,
      default: false, // Google users automatically verified
    },
    // Existing fields
    isPremium: {
      type: Boolean,
      default: false,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    phoneNumber: {
      type: String,
      validate: {
        validator: function(v) {
          return !v || /^\+244\s?9\d{8}$/.test(v);
        },
        message: "Número de telefone angolano inválido"
      }
    },
    lastLogin: {
      type: Date,
      default: Date.now,
    },
    loginCount: {
      type: Number,
      default: 0,
    },
    preferences: {
      notifications: {
        email: { type: Boolean, default: true },
        sms: { type: Boolean, default: false }
      },
      language: {
        type: String,
        enum: ['pt', 'en'],
        default: 'pt'
      }
    }
  },
  {
    timestamps: true,
  }
);

// Compound index for Google users
userSchema.index({ email: 1, googleId: 1 });

// Pre-save middleware to increment login count
userSchema.pre('save', function(next) {
  if (this.isModified('lastLogin')) {
    this.loginCount += 1;
  }
  next();
});

// Virtual for full name display
userSchema.virtual('displayName').get(function() {
  return this.name || this.email.split('@')[0];
});

// Method to check if user can login with password
userSchema.methods.hasLocalAuth = function() {
  return this.password && this.authProvider !== 'google';
};

// Method to update Google profile info
userSchema.methods.updateGoogleProfile = function(googleData) {
  if (googleData.name && !this.name) {
    this.name = googleData.name;
  }
  if (googleData.picture) {
    this.picture = googleData.picture;
  }
  if (googleData.sub && !this.googleId) {
    this.googleId = googleData.sub;
  }
  this.isEmailVerified = true; // Google emails are verified
  return this.save();
};

// Static method to find or create Google user
userSchema.statics.findOrCreateGoogleUser = async function(googleData) {
  const { sub, email, name, picture } = googleData;
  
  let user = await this.findOne({
    $or: [
      { email: email },
      { googleId: sub }
    ]
  });

  if (user) {
    // Update existing user with Google data if needed
    if (!user.googleId) {
      user.googleId = sub;
      user.authProvider = 'google';
      user.isEmailVerified = true;
      if (!user.name) user.name = name;
      if (picture) user.picture = picture;
      await user.save();
    }
    return user;
  }

  // Create new user
  user = new this({
    email: email,
    googleId: sub,
    name: name,
    picture: picture,
    authProvider: 'google',
    isEmailVerified: true,
    password: null
  });

  return user.save();
};

module.exports = mongoose.model("User", userSchema);