import { Request, Response } from 'express';
import { User } from '../models/User';
import nodemailer, { SendMailOptions } from 'nodemailer';
import { compare } from 'bcrypt';

const path = require('path');

const bcrypt = require('bcrypt');

export const ping = (req: Request, res: Response) => {
    res.json({ pong: true });
}

export const register = async (req: Request, res: Response) => {

    const { email, password, name, discipline } = req.body;

    if (email && password && name && discipline) {

        let hasUser = await User.findOne({ where: { email } });
        if (!hasUser) {

            let hashedPassword = await criptografarSenha(password);

            let newUser = await User.create({ email, password: hashedPassword, name, discipline });

            res.status(201);
            return res.json({
                message: "Usuário cadastradado com sucesso.",
                newUser
            });
        } else {
            return res.json({ error: 'E-mail já existe.' });
        }
    }

    return res.json({ error: 'E-mail e/ou senha não enviados.' });;
}

export const login = async (req: Request, res: Response) => {
    if(req.method === 'POST') {

        if (req.body.email && req.body.password) {
            let email: string = req.body.email;
            let password: string = req.body.password;
    
            let user = await User.findOne({
                where: { email }
            });
    
            if (user) {
                let isPasswordCorrect = await compare(password, user.password);
    
                if (isPasswordCorrect) {
                    res.json({ status: true });
                } else {
                    res.json({ status: false });
                }
                return;
            }
        }
    
        res.json({ status: false });
    } else {
        const filePath = path.join('D:/Javascript/SS/Atv02/SS-criptografia/ss-front/login', 'login.html');
        res.sendFile(filePath);
    }
}




export const listAll = async (req: Request, res: Response) => {
    let users = await User.findAll();

    res.json({ users });
}


export const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.params;

    if (!email) {
        return res.json({ error: 'E-mail não fornecido.' });
    }

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.json({ error: 'Usuário não encontrado.' });
        }

        const newPassword = gerarSenhaAleatoria(); // Gerando uma nova senha aleatória

        const hashedPassword = await criptografarSenha(newPassword); // Criptografando a nova senha

        await User.update({ password: hashedPassword }, { where: { email } }); // Atualizando a senha do usuário

        // Configuração do transporte de e-mail usando Nodemailer
        const transporter = nodemailer.createTransport({
            host: 'sandbox.smtp.mailtrap.io',
            port: 2525,
            auth: {
                user: '257f626c782237',
                pass: 'c7e876cdfcf1b6',
            },
        });

        // Montando as opções do e-mail
        const mailOptions = {
            from: 'seu-email@dominio.com',
            to: user.email,
            subject: 'Recuperação de senha',
            text: `Sua senha é: ${newPassword}`, // Enviando a senha do usuário
        };

        // Enviando o e-mail
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Erro ao enviar o e-mail:', error);
                return res.json({ error: 'Ocorreu um erro ao enviar o e-mail.' });
            } else {
                console.log('E-mail enviado:', info.response);
                return res.json({ message: 'Senha enviada por e-mail.' });
            }
        });
    } catch (error) {
        console.error(error);
        return res.json({ error: 'Ocorreu um erro ao processar a solicitação.' });
    }
};

function gerarSenhaAleatoria() {
    const senha = Math.random().toString(36).slice(-8);

    return senha;
}

function criptografarSenha(password: string) {
    const saltRouds = 10;
    const hashedPassword = bcrypt.hash(password, saltRouds);

    return hashedPassword;
}