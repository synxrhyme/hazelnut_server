const services = {
  authService: async (context, event) => {
    const data = event.data;

    try {
      const payload = jwt.verify(data.body.token, SECRET_KEY);

      if (payload.userId !== data.body.userId) {
        return {
          header: "auth_response",
          status: "token_invalid",
          body: { timestamp: Date.now() }
        };
      }

      const user = await User.findOne({ userId: data.body.userId });

      if (!user) {
        return {
          header: "auth_response",
          status: "user_invalid",
          body: { timestamp: Date.now() }
        };
      }

      return {
        header: "auth_response",
        status: "valid",
        body: { timestamp: Date.now() }
      };
    } catch (err) {
      return {
        header: "auth_response",
        status: "token_invalid",
        body: { timestamp: Date.now() }
      };
    }
  }
};
