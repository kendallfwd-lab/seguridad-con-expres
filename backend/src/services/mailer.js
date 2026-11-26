import nodemailer from 'nodemailer';

export function isSmtpConfigured(env) {
  return Boolean(env.SMTP_HOST && env.SMTP_PORT && env.SMTP_FROM);
}

export function createMailer(env) {
  if (!isSmtpConfigured(env)) {
    return {
      configured: false,
      async sendVerificationEmail() {
        return { sent: false, reason: 'SMTP no configurado' };
      },
      async sendPasswordResetEmail() {
        return { sent: false, reason: 'SMTP no configurado' };
      }
    };
  }

  const transport = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_PORT === 465,
    auth: env.SMTP_USER && env.SMTP_PASSWORD
      ? { user: env.SMTP_USER, pass: env.SMTP_PASSWORD }
      : undefined
  });

  const primaryOrigin = env.APP_ORIGIN.split(',')[0].trim().replace(/\/+$/, '');

  return {
    configured: true,
    async sendVerificationEmail({ to, token }) {
      const link = `${primaryOrigin}/?action=verify-email&token=${encodeURIComponent(token)}`;
      await transport.sendMail({
        from: env.SMTP_FROM,
        to,
        subject: 'Verifica tu cuenta en Security Lab',
        text: `Para activar tu cuenta en Security Lab, usa este token o enlace (válido por 24 horas):\n\n${link}\n\nToken: ${token}`
      });
      return { sent: true };
    },
    async sendPasswordResetEmail({ to, token }) {
      const link = `${primaryOrigin}/?action=reset-password&token=${encodeURIComponent(token)}`;
      await transport.sendMail({
        from: env.SMTP_FROM,
        to,
        subject: 'Recuperación de contraseña en Security Lab',
        text: `Recibimos una solicitud para restablecer tu contraseña (válido por 1 hora):\n\n${link}\n\nToken: ${token}`
      });
      return { sent: true };
    }
  };
}
